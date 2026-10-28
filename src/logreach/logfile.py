import logging
import re
from datetime import datetime, tzinfo
from pathlib import Path
from types import TracebackType
from typing import Self, TextIO

from logreach.exceptions import DateTimeNotFound, LogreachError

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
                   datetime_key: str | None = None, datetime_regex: str | None = None,
                   begin: datetime | None = None, end: datetime | None = None,
                   dayfirst: bool = False, timezone: tzinfo | None = None) -> LogConfig:
    """Build the config that tells Logfile how to read timestamps from a
    logfile.

    For json: the timestamp is read from the field datetime_key, which is
    required (TypeError otherwise).
    For syslog, audit and access: the timestamp is the first group of datetime_regex, or of the type's
    default regex from TimestampRegex if none is given.
    dayfirst reads ambiguous dates like 1/9/2026 as day/month.
    timezone is attached to timestamps without one (None: UTC).
    """
    if logtype == LogType.JSON:
        if not datetime_key:
            raise TypeError('json-type needs a datetime_key to identify the timestamp')
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

    def __init__(self, config: LogConfig, logger: logging.Logger):
        self.config: LogConfig = config
        self.logger = logger
        self.filehandle: TextIO | None = None
        self.lineno: int = 0
        # lines skipped because they have no timestamp: the first few as (lineno, line), and a count
        self.unparsed: list[tuple[int, str]] = []
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
        """Return the next line that has a timestamp inside the time window;
        lines without timestamp are recorded in unparsed and skipped."""
        if not self.filehandle:
            raise LogreachError('Logfile is not open for reading')
        for line in self.filehandle:
            self.lineno += 1
            timestamp = self._parse_timestamp(line)
            if timestamp is not None and self.config.in_range(timestamp):
                return Logline(timestamp=timestamp, raw=line, lineno=self.lineno,
                               filename=str(self.config.logfile_path))
        raise StopIteration

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

    def _parse_timestamp(self, line: str) -> datetime | None:
        """Parse the timestamp of line and attach the config's timezone if it
        has none.

        A line without timestamp is recorded in unparsed and returns
        None, or raises DateTimeNotFound if empty timestamps are not
        allowed.
        """
        timestamp = self.config.parse_timestamp(line)
        if timestamp is not None:
            return self.config.with_timezone(timestamp)
        if not self.config.allow_empty_timestamp:
            self.logger.error(f'Unable to parse timestamp in line {self.lineno}: {line}')
            raise DateTimeNotFound(f'Timestamp not found in line {self.lineno}')
        self.unparsed_count += 1
        if len(self.unparsed) < MAX_KEPT_UNPARSED:
            self.unparsed.append((self.lineno, line))
        return None
