from dataclasses import dataclass, field
from typing import Pattern, Optional
from pathlib import Path
from datetime import datetime, timezone
from enum import Enum
from dateutil.parser import parse, ParserError
from logmate.exceptions import DateTimeKeyNotFound, DateTimeNotFound
import json
import re

class LogType(Enum):
    SYSLOG = "syslog"
    AUDIT = "audit"
    ACCESS = "access"
    JSON = "json"

class TimestampRegex(Enum):
    syslog = r'\A(.+?\d{2}:\d{2}:\d{2}\S*)\s+'
    audit = r'\A.*msg=audit\((.+):\d+\):\s+'
    access = r'\A.+?\s\[(.+)\]\s\"'

@dataclass
class LogConfig:
    logfile_path: Path
    begin: Optional[datetime] = field(default=None, kw_only=True)
    end: Optional[datetime] = field(default=None, kw_only=True)
    allow_empty_timestamp: bool = field(default=True, kw_only=True)

    def in_range(self, timestamp: datetime) -> bool:
        if not timestamp:
            return False
        if self.begin:
            if timestamp < self.begin:
                return False
        if self.end:
            if timestamp > self.end:
                return False
        return True


    def parse_timestamp(self, logline: str) -> datetime:
        pass

@dataclass
class LogfileConfig(LogConfig):
    regex_pattern: Pattern
    _unix_timestamp: bool = False

    def parse_timestamp(self, logline: str) -> datetime:
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

@dataclass
class JsonLogfileConfig(LogConfig):
    datetime_key: str

    def parse_timestamp(self, logline: str) -> datetime:
        json_object = json.loads(logline)
        if not self.datetime_key in json_object:
            raise DateTimeKeyNotFound(f"Unable to find timestamp-key \"{self.datetime_key}\" in json-string: {json_object}")
        return parse(json_object[self.datetime_key])

