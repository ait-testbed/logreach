import json
import logging
import os
import re
from typing import Any, Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from logreach.exceptions import DateTimeKeyNotFound, DateTimeNotFound, LogreachError, LogTypeError
from logreach.logfile import Logfile, config_factory
from logreach.schemas.logfileconfig import LogConfig, LogType

# keys that json detection looks for, in this order
JSON_TIMESTAMP_KEYS = ('timestamp', '@timestamp', 'time', 'start-datetime', 'ts')
# specific formats first: the loose syslog regex would match many other formats too
DETECTION_ORDER = (LogType.JSON, LogType.AUDIT, LogType.ACCESS, LogType.SYSLOG)
DEFAULT_TYPES_FILE = 'logtypes.json'
DEFAULT_IGNORES_FILE = 'ignore_list.txt'


def json_timestamp_key(path: str) -> str | None:
    """Return the first known timestamp key in the file's first line."""
    with open(path, 'r') as logfile:
        record = json.loads(logfile.readline())
    if not isinstance(record, dict):
        return None
    return next((key for key in JSON_TIMESTAMP_KEYS if key in record), None)


def create_if_missing(path: str) -> None:
    """Create an empty file at path unless it exists or path is empty."""
    if path and not os.path.exists(path):
        with open(path, 'w'):
            pass


class IgnoreList:
    def __init__(self, ignores_file: str = '', extensions: Iterable[str] = ()):
        self.ignores_file = ignores_file
        # (compiled regex, where it comes from for ignore_reason())
        self.patterns: list[tuple[re.Pattern[str], str]] = []
        if ignores_file:
            self.compile_regex()
        self.add_extensions(extensions)

    def compile_regex(self) -> None:
        """Compile one regex per line, skipping blank lines and # comments."""
        with open(self.ignores_file, 'r') as list_file:
            for line in list_file:
                pattern = line.strip()
                if not pattern or pattern.startswith('#'):
                    continue
                self.patterns.append((re.compile(pattern), f'{self.ignores_file} pattern {pattern}'))

    def add_extensions(self, extensions: Iterable[str]) -> None:
        """Ignore paths ending in one of extensions, e.g. '.gz' or 'gz'."""
        for extension in extensions:
            if not extension.startswith('.'):
                extension = '.' + extension
            self.patterns.append((re.compile(re.escape(extension) + r'\Z'), f'extension {extension}'))

    def ignore_reason(self, path: str) -> str | None:
        """Name the first pattern that matches path, e.g. 'extension .gz', or
        None if path is not ignored."""
        for pattern, source in self.patterns:
            if pattern.search(path):
                return source
        return None


class KnownLogfilePaths:
    def __init__(self, types_file: str = DEFAULT_TYPES_FILE):
        self.types_file = types_file
        self.data: dict[str, dict[str, Any]] = {}
        self._read_file()

    def _read_file(self) -> None:
        with open(self.types_file, 'r') as list_file:
            for line in list_file:
                item = json.loads(line)
                self.data[item['logfile_path']] = item

    def __contains__(self, path: str) -> bool:
        return path in self.data

    def config_for(self, path: str, allow_empty_timestamp: bool = True) -> LogConfig:
        """Build the config stored for path in the types file."""
        entry = self.data[path]
        timezone = None
        if 'timezone' in entry:
            try:
                timezone = ZoneInfo(entry['timezone'])
            except (ZoneInfoNotFoundError, ValueError):
                raise LogreachError(f'Unknown timezone in {self.types_file}: {entry["timezone"]}')
        return config_factory(path, LogType(entry['type']), allow_empty_timestamp=allow_empty_timestamp,
                              datetime_key=entry.get('datetimekey'),
                              datetime_regex=entry.get('datetimeregex'),
                              dayfirst=entry.get('dayfirst', False), timezone=timezone)


class Analyzer:
    def __init__(self, types_file: str = DEFAULT_TYPES_FILE, ignores_file: str = DEFAULT_IGNORES_FILE,
                 auto_create: bool = True, ignored_extensions: Iterable[str] = ()):
        if auto_create:
            create_if_missing(types_file)
            create_if_missing(ignores_file)
        self._types = KnownLogfilePaths(types_file) if types_file else None
        self._ignores = IgnoreList(ignores_file, ignored_extensions)

    @property
    def ignores(self) -> IgnoreList:
        return self._ignores

    def _try_logtype(self, path: str, logtype: LogType, allow_empty_timestamp: bool = True) -> LogConfig:
        """Can this file be read as logtype?

        If yes return config if no raise LogTypeError.
        """
        try:
            datetime_key = json_timestamp_key(path) if logtype == LogType.JSON else None
            if logtype == LogType.JSON and datetime_key is None:
                raise LogTypeError(f'No known timestamp key in {path}')
            config = config_factory(path, logtype, datetime_key=datetime_key,
                                    allow_empty_timestamp=allow_empty_timestamp)
            # get back first line that parses as logtype
            with Logfile(config, logger=logging.getLogger()) as lf:
                first_line = next(lf, None)
        except UnicodeDecodeError:
            raise LogTypeError(f'Unsupported filetype: {path}')
        except json.decoder.JSONDecodeError:
            raise LogTypeError(f'Not a valid json file: {path}')

        if first_line is None:
            raise LogTypeError(f'No line in {path} parses as {logtype.value}')
        return config

    def detect_config(self, path: str, allow_empty_timestamp: bool = True) -> LogConfig:
        """Return the config from the types file, or of the first log type in
        DETECTION_ORDER that can read the file.

        If none work or the file is empty, raise LogTypeError.
        """
        if self._types and path in self._types:
            return self._types.config_for(path, allow_empty_timestamp)
        if os.path.getsize(path) == 0:
            raise LogTypeError(f'{path} is empty')

        for logtype in DETECTION_ORDER:
            try:
                return self._try_logtype(path, logtype, allow_empty_timestamp=allow_empty_timestamp)
            except (LogTypeError, DateTimeKeyNotFound, DateTimeNotFound):
                continue  # try matching the next LogType
        raise LogTypeError(f'Unable to determine logtype for: {path}')
