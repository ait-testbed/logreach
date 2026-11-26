import gzip
import logging
import os
import re
from datetime import datetime, tzinfo
from pathlib import Path
from types import TracebackType
from typing import Self, TextIO

from logreach.exceptions import DateTimeNotFound, LogreachError, NoTimestamp

from .schemas.logfileconfig import JsonLogConfig, LogConfig, LogType, RegexLogConfig, TimestampRegex
from .schemas.logline import Logline

logger = logging.getLogger(__name__)

# lines without timestamp that Logfile keeps for reporting; the rest are only counted
MAX_KEPT_UNPARSED = 5

DEFAULT_TIMESTAMP_REGEX = {
    LogType.SYSLOG: TimestampRegex.SYSLOG,
    LogType.AUDIT: TimestampRegex.AUDIT,
    LogType.ACCESS: TimestampRegex.ACCESS,
}


def open_text(path: str | Path, errors: str | None = None) -> TextIO:
    """Open path for reading text, decompressing it if it is gzip (detected by
    its magic bytes, not its name)."""
    with open(path, 'rb') as file:
        is_gzip = file.read(2) == b'\x1f\x8b'
    return gzip.open(path, 'rt', errors=errors) if is_gzip else open(path, 'r', errors=errors)


def is_empty(path: str | Path) -> bool:
    """Has path no text?

    A compressed empty file still has bytes.
    """
    if os.path.getsize(path) == 0:  # also FIFOs and sockets, which open() would block on or fail
        return True
    # errors='replace': a binary file is not empty, detection reports it
    with open_text(path, errors='replace') as file:
        return file.read(1) == ''


def config_factory(logfile_path: str, logtype: LogType, allow_empty_timestamp: bool = True,
                   datetime_key: str | None = None, datetime_regex: str | None = None,
                   begin: datetime | None = None, end: datetime | None = None,
                   dayfirst: bool = False, timezone: tzinfo | None = None) -> LogConfig:
    """Build the config that tells Logfile how to read timestamps from a
    logfile.

    For json: the timestamp is read from the field datetime_key, which is
    required (ValueError otherwise).
    For syslog, audit and access: the timestamp is the first group of datetime_regex, or of the type's
    default regex from TimestampRegex if none is given.
    dayfirst reads ambiguous dates like 1/9/2026 as day/month.
    timezone is attached to timestamps without one (None: UTC).
    """
    if logtype == LogType.JSON:
        if not datetime_key:
            raise ValueError('type json needs a datetimekey for the timestamp')
        return JsonLogConfig(logfile_path=Path(logfile_path), datetime_key=datetime_key,
                             begin=begin, end=end, allow_empty_timestamp=allow_empty_timestamp,
                             dayfirst=dayfirst, timezone=timezone)

    regex = datetime_regex or DEFAULT_TIMESTAMP_REGEX[logtype].value
    return RegexLogConfig(logfile_path=Path(logfile_path), regex_pattern=re.compile(regex),
                          begin=begin, end=end, allow_empty_timestamp=allow_empty_timestamp,
                          dayfirst=dayfirst, timezone=timezone)


class Logfile:
    """Reads the lines of a logfile that are in the config's time window.

    The file is opened by `with Logfile(...)` (or open()) and closed on
    leaving the block (or close()), not when the object is created.
    """

    def __init__(self, config: LogConfig):
        self.config: LogConfig = config
        self.filehandle: TextIO | None = None
        self.lineno: int = 0
        # of the last line with timestamp: lines without one after it share its place in the time window
        self.last_timestamp: datetime | None = None
        # lines skipped because they have no timestamp: the first few as (lineno, reason, line), and a count
        self.unparsed: list[tuple[int, str, str]] = []
        self.unparsed_count: int = 0

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None,
                 traceback: TracebackType | None) -> None:
        self.close()

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> Logline:
        """Return the next line inside the time window that matches the
        config's grep.

        A line without timestamp is returned too, with timestamp None
        and the reason, and recorded in unparsed. It belongs to the last
        line with timestamp before it (e.g. a stack trace), so it is in
        the time window if that line is.
        """
        if not self.filehandle:
            raise LogreachError('Logfile is not open for reading')
        for line in self.filehandle:
            self.lineno += 1
            timestamp, reason = self._parse_timestamp(line)
            if timestamp is not None:
                self.last_timestamp = timestamp
            if self.config.in_range(self.last_timestamp) and self.config.matches(line):
                return Logline(timestamp=timestamp, raw=line, lineno=self.lineno,
                               filename=str(self.config.logfile_path), reason=reason)
        raise StopIteration

    def open(self) -> None:
        if not self.filehandle:
            self.filehandle = open_text(self.config.logfile_path)

    def close(self) -> None:
        if self.filehandle:
            self.filehandle.close()
            self.filehandle = None
            self.lineno = 0
            self.last_timestamp = None
        else:
            logger.warning("Won't close the file since it is not open")

    def _parse_timestamp(self, line: str) -> tuple[datetime | None, str | None]:
        """Return the timestamp of line, with the config's timezone attached if
        it has none, and None as reason.

        A line without timestamp is recorded in unparsed and returns
        (None, why), or raises DateTimeNotFound if empty timestamps are
        not allowed.
        """
        reason = 'no timestamp'
        try:
            timestamp = self.config.parse_timestamp(line)
        except NoTimestamp as e:
            timestamp, reason = None, str(e)
        if timestamp is not None:
            return self.config.with_timezone(timestamp), None
        if not self.config.allow_empty_timestamp:
            raise DateTimeNotFound(f'line {self.lineno}: {reason}')
        self.unparsed_count += 1
        if len(self.unparsed) < MAX_KEPT_UNPARSED:
            self.unparsed.append((self.lineno, reason, line))
        return None, reason
