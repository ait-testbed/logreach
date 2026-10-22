from dataclasses import dataclass, field
from typing import Pattern, Optional
from pathlib import Path
from datetime import datetime, timezone
from enum import Enum
from dateutil.parser import parse, ParserError
from logreach.exceptions import DateTimeKeyNotFound
import json
import re


class LogType(Enum):
    SYSLOG = "syslog"
    AUDIT = "audit"
    ACCESS = "access"
    JSON = "json"


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

    def parse_timestamp(self, logline: str) -> Optional[datetime]:
        pass


@dataclass
class RegexLogConfig(LogConfig):
    regex_pattern: Pattern[str]
    _unix_timestamp: bool = False

    def parse_timestamp(self, logline: str) -> Optional[datetime]:
        match = re.match(self.regex_pattern, logline)
        if match:
            parsed_match = match.group(1)
            if self._unix_timestamp:
                return datetime.fromtimestamp(float(parsed_match), timezone.utc)
            try:
                return parse(parsed_match, fuzzy=True)
            except ParserError as e:
                if re.match(r'\A\d+\.\d+\Z', parsed_match):
                    self._unix_timestamp = True
                    return datetime.fromtimestamp(float(parsed_match), timezone.utc)
                else:
                    print(e)
        return None


@dataclass
class JsonLogConfig(LogConfig):
    datetime_key: str

    def parse_timestamp(self, logline: str) -> Optional[datetime]:
        json_object = json.loads(logline)
        if self.datetime_key not in json_object:
            raise DateTimeKeyNotFound(
                f"Unable to find timestamp-key \"{self.datetime_key}\" in json-string: {json_object}")
        return parse(json_object[self.datetime_key])
