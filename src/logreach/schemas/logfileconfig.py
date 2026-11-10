import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, tzinfo
from enum import Enum
from pathlib import Path
from typing import Pattern

from dateutil.parser import ParserError, parse

from logreach.exceptions import NoTimestamp


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
    begin: datetime | None = field(default=None, kw_only=True)
    end: datetime | None = field(default=None, kw_only=True)
    allow_empty_timestamp: bool = field(default=True, kw_only=True)
    # read ambiguous dates like 1/9/2026 as 1 September; also flips ISO dates, so set it only per file
    dayfirst: bool = field(default=False, kw_only=True)
    # timezone of timestamps that have none, e.g. classic syslog; None means UTC
    timezone: tzinfo | None = field(default=None, kw_only=True)

    def with_timezone(self, timestamp: datetime) -> datetime:
        """Attach the config's timezone (UTC if unset) to a timestamp without
        one; timestamps with a timezone are kept as they are."""
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=self.timezone or timezone.utc)
        return timestamp

    def in_range(self, timestamp: datetime) -> bool:
        # both sides with a timezone: comparing one with and one without raises TypeError
        timestamp = self.with_timezone(timestamp)
        after_begin = self.begin is None or timestamp >= self.with_timezone(self.begin)
        before_end = self.end is None or timestamp <= self.with_timezone(self.end)
        return after_begin and before_end

    @property
    def default_datetime(self) -> datetime | None:
        """Supplies the parts a timestamp lacks, e.g. the year of classic
        syslog stamps: January 1st of the year of begin (or end).

        None means today, as dateutil does by default.
        """
        reference = self.begin or self.end
        return datetime(reference.year, 1, 1) if reference else None

    def parse_timestamp(self, logline: str) -> datetime | None:
        pass

    @property
    def timezone_name(self) -> str:
        """Name of the timezone attached to timestamps without one, e.g. 'UTC'
        or 'Europe/Vienna'."""
        return str(self.timezone or timezone.utc)

    def describe(self) -> str:
        """Name how this config reads timestamps, e.g. 'syslog (UTC)'."""
        return f'{type(self).__name__} ({self.timezone_name})'


@dataclass
class RegexLogConfig(LogConfig):
    regex_pattern: Pattern[str]
    # switches to epoch parsing after the first epoch timestamp, e.g. audit logs: state, not a setting
    _unix_timestamp: bool = field(default=False, init=False, repr=False, compare=False)

    def describe(self) -> str:
        try:
            name = TimestampRegex(self.regex_pattern.pattern).name.lower()
        except ValueError:  # not one of the built-in regexes
            name = f'custom regex {self.regex_pattern.pattern}'
        return f'{name} ({self.timezone_name})'

    def parse_timestamp(self, logline: str) -> datetime | None:
        match = self.regex_pattern.match(logline)
        if not match:
            return None

        raw_timestamp = match.group(1)
        if self._unix_timestamp:
            return datetime.fromtimestamp(float(raw_timestamp), timezone.utc)
        try:
            return parse(raw_timestamp, fuzzy=True, default=self.default_datetime, dayfirst=self.dayfirst)
        except ParserError:
            if re.match(r'\A\d+\.\d+\Z', raw_timestamp):
                self._unix_timestamp = True
                return datetime.fromtimestamp(float(raw_timestamp), timezone.utc)
        return None


@dataclass
class JsonLogConfig(LogConfig):
    datetime_key: str

    def describe(self) -> str:
        return f'json ({self.datetime_key}, {self.timezone_name})'

    def parse_timestamp(self, logline: str) -> datetime | None:
        """Raises NoTimestamp saying why a line has none: Logfile reports it
        and reads on."""
        try:
            record = json.loads(logline)
        except json.JSONDecodeError as e:  # e.g. a line cut off mid-write
            raise NoTimestamp(f'invalid JSON ({e.msg}, column {e.colno})')
        if not isinstance(record, dict):
            raise NoTimestamp('no JSON object')
        if self.datetime_key not in record:
            raise NoTimestamp(f'no "{self.datetime_key}" key')
        value = record[self.datetime_key]
        try:
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                # shortcut: seconds only; epochs in milliseconds are out of range and count as no date
                return datetime.fromtimestamp(value, timezone.utc)
            if isinstance(value, str):
                return parse(value, default=self.default_datetime, dayfirst=self.dayfirst)
        except (ParserError, ValueError, OverflowError, OSError):
            pass
        raise NoTimestamp(f'"{self.datetime_key}" is no date')
