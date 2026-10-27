import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Pattern

from dateutil.parser import ParserError, parse

from logreach.exceptions import DateTimeKeyNotFound


class LogType(Enum):
    SYSLOG = 'syslog'
    AUDIT = 'audit'
    ACCESS = 'access'
    JSON = 'json'


class TimestampRegex(Enum):
    SYSLOG = r'\A(.+?\d{2}:\d{2}:\d{2}\S*)\s+'
    AUDIT = r'\A.*msg=audit\((.+):\d+\):\s+'
    ACCESS = r'\A.+?\s\[(.+)\]\s\"'


@dataclass
class LogConfig:
    logfile_path: Path
    begin: Optional[datetime] = field(default=None, kw_only=True)
    end: Optional[datetime] = field(default=None, kw_only=True)
    allow_empty_timestamp: bool = field(default=True, kw_only=True)

    def in_range(self, timestamp: datetime) -> bool:
        after_begin = self.begin is None or timestamp >= self.begin
        before_end = self.end is None or timestamp <= self.end
        return after_begin and before_end

    @property
    def default_datetime(self) -> Optional[datetime]:
        """Supplies the parts a timestamp lacks, e.g. the year of classic
        syslog stamps: January 1st of the year of begin (or end).

        None means today, as dateutil does by default.
        """
        reference = self.begin or self.end
        return datetime(reference.year, 1, 1) if reference else None

    def parse_timestamp(self, logline: str) -> Optional[datetime]:
        pass

    def describe(self) -> str:
        """Name how this config reads timestamps, e.g. 'syslog'."""
        return type(self).__name__


@dataclass
class RegexLogConfig(LogConfig):
    regex_pattern: Pattern[str]
    _unix_timestamp: bool = False

    def describe(self) -> str:
        try:
            return TimestampRegex(self.regex_pattern.pattern).name.lower()
        except ValueError:  # not one of the built-in regexes
            return f'custom regex {self.regex_pattern.pattern}'

    def parse_timestamp(self, logline: str) -> Optional[datetime]:
        match = self.regex_pattern.match(logline)
        if not match:
            return None

        raw_timestamp = match.group(1)
        if self._unix_timestamp:
            return datetime.fromtimestamp(float(raw_timestamp), timezone.utc)
        try:
            return parse(raw_timestamp, fuzzy=True, default=self.default_datetime)
        except ParserError:
            if re.match(r'\A\d+\.\d+\Z', raw_timestamp):
                self._unix_timestamp = True
                return datetime.fromtimestamp(float(raw_timestamp), timezone.utc)
        return None


@dataclass
class JsonLogConfig(LogConfig):
    datetime_key: str

    def describe(self) -> str:
        return f'json ({self.datetime_key})'

    def parse_timestamp(self, logline: str) -> Optional[datetime]:
        record = json.loads(logline)
        if self.datetime_key not in record:
            raise DateTimeKeyNotFound(
                f'Unable to find timestamp-key "{self.datetime_key}" in json-string: {record}')
        return parse(record[self.datetime_key], default=self.default_datetime)
