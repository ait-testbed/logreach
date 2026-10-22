import json
import logging
import os
import re
from typing import Any, Optional

from logreach.exceptions import DateTimeKeyNotFound
from logreach.logfile import Logfile, config_factory
from logreach.schemas.logfileconfig import LogConfig, LogType
from logtype.exceptions import FoundInTypes, IgnoredFile, LogFileEmpty, LogTypeError

# key that json detection reads the timestamp from
DEFAULT_JSON_TIMESTAMP_KEY = 'time'
DEFAULT_TYPES_FILE = 'logtypes.json'
DEFAULT_IGNORES_FILE = 'ignore_list.txt'


def create_if_missing(path: str) -> None:
    """Create an empty file at path unless it exists or path is empty."""
    if path and not os.path.exists(path):
        with open(path, 'w'):
            pass


class IgnoreList:
    def __init__(self, ignores_file: str):
        self.ignores_file = ignores_file
        self.patterns: list[re.Pattern[str]] = []
        self.compile_regex()

    def compile_regex(self) -> None:
        """Compile one regex per line, skipping blank lines and # comments."""
        with open(self.ignores_file, 'r') as list_file:
            for line in list_file:
                pattern = line.strip()
                if not pattern or pattern.startswith('#'):
                    continue
                self.patterns.append(re.compile(pattern))

    def is_ignored(self, path: str) -> bool:
        for pattern in self.patterns:
            if pattern.search(path):
                return True
        return False


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


class Analyzer:
    def __init__(self, types_file: str = DEFAULT_TYPES_FILE, ignores_file: str = DEFAULT_IGNORES_FILE,
                 auto_create: bool = True):
        if auto_create:
            create_if_missing(types_file)
            create_if_missing(ignores_file)
        self._types = KnownLogfilePaths(types_file) if types_file else None
        self._ignores = IgnoreList(ignores_file) if ignores_file else None

    @property
    def types(self) -> Optional[KnownLogfilePaths]:
        return self._types

    @property
    def ignores(self) -> Optional[IgnoreList]:
        return self._ignores

    def check_not_skipped(self, path: str) -> None:
        """Raise a SkipFile subclass if logtype should skip the file.

        Raises FoundInTypes if the path is a known logfile path and
        IgnoredFile if it matches the ignore list.
        """
        if self._types and path in self._types:
            raise FoundInTypes
        if self._ignores and self._ignores.is_ignored(path):
            raise IgnoredFile

    def _try_logtype(self, path: str, logtype: LogType, allow_empty_timestamp: bool = True) -> LogConfig:
        """Can this file be read as logtype?

        If yes return config if no raise LogTypeError. If the file is
        empty, raise LogFileEmpty.
        """

        config = config_factory(path, logtype, datetime_key=DEFAULT_JSON_TIMESTAMP_KEY,
                                allow_empty_timestamp=allow_empty_timestamp)
        try:
            # get back first line that parses as logtype
            with Logfile(config, logger=logging.getLogger()) as lf:
                first_line = next(lf, None)
        except UnicodeDecodeError:
            raise LogTypeError(f'Unsupported filetype: {path}')
        except json.decoder.JSONDecodeError:
            raise LogTypeError(f'Not a valid json file: {path}')

        if first_line is None:
            raise LogFileEmpty(f'{path} is empty')
        return config

    def detect_config(self, path: str, allow_empty_timestamp: bool = True) -> LogConfig:
        """Try each log type on the file and return the config of the first one
        that works.

        If none work, raise LogTypeError.
        """

        for logtype in LogType:
            try:
                return self._try_logtype(path, logtype, allow_empty_timestamp=allow_empty_timestamp)
            # must come before LogTypeError, which LogFileEmpty subclasses
            except LogFileEmpty:
                raise
            except DateTimeKeyNotFound as e:
                raise LogTypeError(f'Error in {path}: {e}')
            except LogTypeError:
                continue  # try matching the next LogType
        raise LogTypeError(f'Unable to determine logtype for: {path}')
