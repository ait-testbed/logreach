from logreach.exceptions import LogreachError,NotInRange, DateTimeNotFound
from .schemas.logfileconfig import LogfileConfig,LogConfig,JsonLogfileConfig,TimestampRegex,LogType
from .schemas.logline import Logline
from typing import Optional
from datetime import datetime
from pathlib import Path
import logging
import re

def config_factory(logfile_path: str, file_type: LogType, allow_empty_timestamp=True, datetimekey: Optional[str] = None, datetimeregex: Optional[str] = None, begin: Optional[datetime] = None, end: Optional[datetime] = None) -> LogConfig:
    if file_type == LogType.AUDIT:
        if datetimeregex:
            regex_pattern = re.compile(datetimeregex)
        else:
            regex_pattern = re.compile(TimestampRegex.audit.value)
        return LogfileConfig(logfile_path=Path(logfile_path), regex_pattern=regex_pattern, begin=begin, end=end, allow_empty_timestamp=allow_empty_timestamp)
    if file_type == LogType.ACCESS:
        if datetimeregex:
            regex_pattern = re.compile(datetimeregex)
        else:
            regex_pattern = re.compile(TimestampRegex.access.value)
        return LogfileConfig(logfile_path=Path(logfile_path), regex_pattern=regex_pattern, begin=begin, end=end, allow_empty_timestamp=allow_empty_timestamp)
    elif file_type == LogType.SYSLOG:
        if datetimeregex:
            regex_pattern = re.compile(datetimeregex)
        else:
            regex_pattern = re.compile(TimestampRegex.syslog.value)
        return LogfileConfig(logfile_path=Path(logfile_path), regex_pattern=regex_pattern, begin=begin, end=end, allow_empty_timestamp=allow_empty_timestamp)
    elif file_type == LogType.JSON:
        if not datetimekey:
            raise TypeError("json-type needs a datetimekey to identify the timestamp")
        return JsonLogfileConfig(logfile_path=Path(logfile_path), datetime_key=datetimekey, begin=begin, end=end, allow_empty_timestamp=allow_empty_timestamp)


class Logfile:
    def __init__(self, config: LogfileConfig, logger: logging.Logger):
        self.config: LogfileConfig = config
        self.filehandle = None
        self.lineno: int = 0
        self.open()
        self.logger = logger

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __iter__(self):
        return self

    def __next__(self):
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

    def _parse_timestamp(self, line: str) -> datetime:
        return self.config.parse_timestamp(line)

    def readline(self) -> Optional[Logline]:
        if self.filehandle:
            logline = self.filehandle.readline()
            if not logline:
                return None
            timestamp: datetime = self._parse_timestamp(logline)
            if not self.config.allow_empty_timestamp and not timestamp:
                self.logger.error(f"Unable to parse timestamp: {logline}")
                raise DateTimeNotFound("Timestamp not found")

            self.lineno = self.lineno+1
            # continue with next line if timestamp is not in range
            if not self.config.in_range(timestamp):
                raise NotInRange(f"line number {self.lineno} is not in timerange")
            return Logline(timestamp=timestamp, msg=logline, lineno=self.lineno, filename=str(self.config.logfile_path))
        else:
            raise LogreachError("Logfile is not open for reading")
            
        
