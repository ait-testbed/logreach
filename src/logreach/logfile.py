import logging
import re
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Optional, Self, TextIO

from logreach.exceptions import DateTimeNotFound, LogreachError, NotInRange

from .schemas.logfileconfig import JsonLogConfig, LogConfig, LogType, RegexLogConfig, TimestampRegex
from .schemas.logline import Logline

# lines without timestamp that Logfile keeps for reporting; the rest are only counted
MAX_KEPT_UNPARSED = 5

DEFAULT_TIMESTAMP_REGEX = {
    LogType.SYSLOG: TimestampRegex.SYSLOG,
    LogType.AUDIT: TimestampRegex.AUDIT,
    LogType.ACCESS: TimestampRegex.ACCESS,
}


def config_factory(logfile_path: str, logtype: LogType, allow_empty_timestamp: bool = True,
                   datetime_key: Optional[str] = None, datetime_regex: Optional[str] = None,
                   begin: Optional[datetime] = None, end: Optional[datetime] = None) -> LogConfig:
    """Build the config that tells Logfile how to read timestamps from a
    logfile.

    For json: the timestamp is read from the field datetime_key, which is
    required (TypeError otherwise).
    For syslog, audit and access: the timestamp is the first group of datetime_regex, or of the type's
    default regex from TimestampRegex if none is given.
    """
    if logtype == LogType.JSON:
        if not datetime_key:
            raise TypeError('json-type needs a datetime_key to identify the timestamp')
        return JsonLogConfig(logfile_path=Path(logfile_path), datetime_key=datetime_key,
                             begin=begin, end=end, allow_empty_timestamp=allow_empty_timestamp)

    regex = datetime_regex or DEFAULT_TIMESTAMP_REGEX[logtype].value
    return RegexLogConfig(logfile_path=Path(logfile_path), regex_pattern=re.compile(regex),
                          begin=begin, end=end, allow_empty_timestamp=allow_empty_timestamp)


class Logfile:
    def __init__(self, config: LogConfig, logger: logging.Logger):
        self.config: LogConfig = config
        self.filehandle: Optional[TextIO] = None
        self.lineno: int = 0
        # lines skipped because they have no timestamp: the first few as (lineno, line), and a count
        self.unparsed: list[tuple[int, str]] = []
        self.unparsed_count: int = 0
        self.open()
        self.logger = logger

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(self, exc_type: Optional[type[BaseException]], exc_value: Optional[BaseException],
                 traceback: Optional[TracebackType]) -> None:
        self.close()

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> Logline:
        while True:
            try:
                line = self.readline()
                if line is None:
                    raise StopIteration
                return line
            # continue with next line if timestamp is not in range
            except NotInRange:
                continue

    def open(self) -> None:
        if not self.filehandle:
            self.filehandle = open(self.config.logfile_path, 'r')

    def close(self) -> None:
        if self.filehandle:
            self.filehandle.close()
            self.filehandle = None
            self.lineno = 0
        else:
            self.logger.warning("Won't close the file since it is not open")

    def readline(self) -> Optional[Logline]:
        if not self.filehandle:
            raise LogreachError('Logfile is not open for reading')

        line = self.filehandle.readline()
        if not line:
            return None

        timestamp = self.config.parse_timestamp(line)
        if timestamp is None and not self.config.allow_empty_timestamp:
            self.logger.error(f'Unable to parse timestamp: {line}')
            raise DateTimeNotFound('Timestamp not found')

        self.lineno += 1
        if timestamp is None:
            self.unparsed_count += 1
            if len(self.unparsed) < MAX_KEPT_UNPARSED:
                self.unparsed.append((self.lineno, line))
        # __next__ skips lines without timestamp or outside the time window
        if timestamp is None or not self.config.in_range(timestamp):
            raise NotInRange(f'line number {self.lineno} is not in timerange')

        return Logline(timestamp=timestamp, raw=line, lineno=self.lineno,
                       filename=str(self.config.logfile_path))
