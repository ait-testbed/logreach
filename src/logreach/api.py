"""Python API: what the logreach command does, without printing, exiting or
asking questions."""

import logging
import os
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, tzinfo
from enum import Enum

from logreach.analyzer import Analyzer
from logreach.exceptions import FILE_ERRORS, LogTypeError
from logreach.logfile import Logfile, config_factory, is_empty
from logreach.schemas.logfileconfig import LogConfig, LogType
from logreach.schemas.logline import Logline

logger = logging.getLogger(__name__)

# characters of a log line shown in a problem message; the line number leads to the rest
MAX_SHOWN_CHARS = 200


def shortened(text: str) -> str:
    return text if len(text) <= MAX_SHOWN_CHARS else text[:MAX_SHOWN_CHARS] + '…'


class FileStatus(Enum):
    READ = 'read'  # its lines follow
    SKIPPED = 'skipped'  # ignored or empty, no problem
    UNDETERMINED = 'undetermined'  # no log type fits
    FAILED = 'failed'  # an error stopped reading it


@dataclass
class FileEvent:
    """What happens to a file, yielded by Logreach.read() before its lines."""

    path: str
    status: FileStatus
    # READ: how the file is read, e.g. 'syslog (UTC)'; else why it is skipped, undetermined or failed
    message: str
    config: LogConfig | None = None  # set for READ


@dataclass
class Problems:
    """Problems collected while reading, so a run never stops halfway."""

    messages: list[str] = field(default_factory=list)
    unparsed_lines: int = 0
    undetermined_files: int = 0
    failed_files: int = 0

    def add_unparsed(self, path: str, logfile: Logfile) -> None:
        """Add the lines of path that had no timestamp: the ones Logfile kept,
        plus a count of the rest."""
        self.messages.extend(f'{path}:{lineno}: {reason}: {shortened(line.rstrip())}'
                             for lineno, reason, line in logfile.unparsed)
        not_kept = logfile.unparsed_count - len(logfile.unparsed)
        if not_kept:
            self.messages.append(f'{path}: ... and {not_kept} more lines without timestamp')
        self.unparsed_lines += logfile.unparsed_count

    def add_undetermined(self, message: str) -> None:
        self.messages.append(message)
        self.undetermined_files += 1

    def add_failed(self, path: str, error: Exception) -> None:
        self.messages.append(f'{path}: {error}')
        self.failed_files += 1


def iter_logfiles(path: str, analyzer: Analyzer) -> Iterator[tuple[str, str | None]]:
    """Yield (file, why it is ignored or None): path itself if it is a file,
    else every file below it."""
    if not os.path.isdir(path):
        yield path, None  # named explicitly, so the ignore list does not apply
        return
    # a dump may hold symlinks: linked directories are not entered (no loops), linked files outside path
    # are skipped (no reading e.g. /etc/shadow)
    top = os.path.realpath(path)
    for root, _dirs, files in os.walk(path):
        for file in files:
            filepath = os.path.join(root, file)
            target = os.path.realpath(filepath)
            if os.path.islink(filepath) and os.path.commonpath([top, target]) != top:
                yield filepath, f'symlink to {target} outside {path}'
            else:
                yield filepath, analyzer.ignores.ignore_reason(filepath)


class Logreach:
    """Reads logfiles, or every file in a directory, detecting the log type of
    each.

    The options apply to every file. types_file and ignores_file are
    None by default: then no file is read or created. The problems of
    the last read() are collected in self.problems.

    on_undetermined(path, error, analyzer) is called for a file whose
    type is not detected; returning True means the answer was saved in
    the types file or ignore list, and the file is looked at again.
    """

    def __init__(self, *, logtype: LogType | str | None = None, datetime_key: str | None = None,
                 datetime_regex: str | None = None, dayfirst: bool = False, timezone: tzinfo = UTC,
                 begin: datetime | None = None, end: datetime | None = None, grep: Iterable[str] = (),
                 ignore_case: bool = False, require_timestamp: bool = False, fail_fast: bool = False,
                 types_file: str | None = None, ignores_file: str | None = None,
                 ignored_extensions: Iterable[str] = (),
                 on_undetermined: Callable[[str, LogTypeError, Analyzer], bool] | None = None):
        self.logtype = LogType(logtype) if logtype else None
        if self.logtype == LogType.JSON and not datetime_key:
            raise ValueError('logtype json requires datetime_key')
        if (datetime_key or datetime_regex) and not self.logtype:
            raise ValueError('datetime_key and datetime_regex require logtype')
        if datetime_regex:
            try:
                re.compile(datetime_regex)
            except re.error as e:
                raise ValueError(f'invalid datetime_regex {datetime_regex!r}: {e}')
        flags = re.IGNORECASE if ignore_case else 0
        try:
            self.grep = [re.compile(pattern, flags) for pattern in grep]
        except re.error as e:
            raise ValueError(f'invalid grep regex {e.pattern!r}: {e}')
        for name, value in (('begin', begin), ('end', end)):
            if value is not None and not isinstance(value, datetime):
                raise TypeError(f'{name} must be a datetime, not {type(value).__name__}')
        # begin / end without timezone are meant in timezone, for every file
        self.begin = begin.replace(tzinfo=timezone) if begin and begin.tzinfo is None else begin
        self.end = end.replace(tzinfo=timezone) if end and end.tzinfo is None else end

        self.datetime_key = datetime_key
        self.datetime_regex = datetime_regex
        self.dayfirst = dayfirst
        self.timezone = timezone
        self.require_timestamp = require_timestamp
        self.fail_fast = fail_fast
        self.on_undetermined = on_undetermined
        # raises LogreachError for a broken types file: nothing could be read right
        self.analyzer = Analyzer(types_file=types_file or '', ignores_file=ignores_file or '',
                                 ignored_extensions=ignored_extensions)
        self.problems = Problems()

    def read(self, path: str | os.PathLike[str]) -> Iterator[Logline | FileEvent]:
        """Yield, file by file, a FileEvent and then the file's lines in order.

        Lines without timestamp are yielded too (timestamp None, reason
        set). Problems do not stop the run; they are collected in
        self.problems, which starts empty for each read. With fail_fast,
        reading stops at the first problem.
        """
        self.problems = Problems()
        for filepath, ignored in iter_logfiles(os.fspath(path), self.analyzer):
            try:
                yield from self._read_file(filepath, ignored)
            except FILE_ERRORS as e:
                self.problems.add_failed(filepath, e)
                yield FileEvent(filepath, FileStatus.FAILED, str(e))
            if self.fail_fast and self.problems.messages:
                return

    def check(self, path: str | os.PathLike[str]) -> Iterator[FileEvent]:
        """Yield only the FileEvent of each file; the files are still read, to
        collect their problems."""
        return (event for event in self.read(path) if isinstance(event, FileEvent))

    def make_config(self, path: str) -> LogConfig:
        """Build the config from logtype, else from the types file or
        detection.

        Raises LogTypeError if no log type fits.
        """
        allow_empty_timestamp = not self.require_timestamp
        if self.logtype:
            config = config_factory(path, self.logtype, allow_empty_timestamp=allow_empty_timestamp,
                                    datetime_key=self.datetime_key, datetime_regex=self.datetime_regex,
                                    begin=self.begin, end=self.end, dayfirst=self.dayfirst,
                                    timezone=self.timezone)
        else:
            config = self.analyzer.detect_config(path, allow_empty_timestamp=allow_empty_timestamp,
                                                 begin=self.begin, end=self.end, dayfirst=self.dayfirst,
                                                 timezone=self.timezone)
        config.grep = self.grep
        return config

    def _read_file(self, path: str, ignored: str | None) -> Iterator[Logline | FileEvent]:
        if ignored:
            skip_reason = f'ignored: {ignored}'
        elif is_empty(path):
            skip_reason = 'empty'
        else:
            skip_reason = None
        if skip_reason:
            logger.debug('%s: skipped: %s', path, skip_reason)
            yield FileEvent(path, FileStatus.SKIPPED, skip_reason)
            return

        try:
            config = self.make_config(path)
        except LogTypeError as e:
            if not (self.on_undetermined and self.on_undetermined(path, e, self.analyzer)):
                self.problems.add_undetermined(str(e))
                yield FileEvent(path, FileStatus.UNDETERMINED, str(e))
                return
            # the answer is in the ignore list or the types file now
            ignored = self.analyzer.ignores.ignore_reason(path)
            if ignored:
                yield FileEvent(path, FileStatus.SKIPPED, f'ignored: {ignored}')
                return
            config = self.make_config(path)

        logger.debug('%s: reading as %s', path, config.describe())
        yield FileEvent(path, FileStatus.READ, config.describe(), config)
        with Logfile(config) as logfile:
            try:
                for line in logfile:
                    # checked before yielding: reading this line may have skipped one without timestamp
                    if self.fail_fast and logfile.unparsed_count:
                        break
                    yield line
            finally:
                self.problems.add_unparsed(path, logfile)
