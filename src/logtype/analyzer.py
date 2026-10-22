from logtype.exceptions import FoundInTypes, IgnoredFile, LogTypeException, LogFileEmpty
from logreach.exceptions import DateTimeKeyNotFound
from logreach.schemas.logfileconfig import LogType, LogConfig
from logreach.logfile import config_factory, Logfile
import logging
import json
import re
import os
from typing import Any, Optional


def create_if_missing(path: str) -> None:
    """Create an empty file at path unless it exists or path is empty."""
    if path and not os.path.exists(path):
        with open(path, 'w'):
            pass


class IgnoresList:
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
            if re.search(pattern, path):
                return True
        return False


class TypesList:
    def __init__(self, types_file: str = "logtypes.json"):
        self.types_file = types_file
        self.data: dict[str, dict[str, Any]] = {}
        self._read_file()

    def _read_file(self) -> None:
        with open(self.types_file, 'r') as list_file:
            for line in list_file:
                item = json.loads(line)
                self.data[item["logfile_path"]] = item

    def is_in_database(self, path: str) -> bool:
        return path in self.data


class Analyzer:
    def __init__(self, types_file: str = "logtypes.json", ignores_file: str = "ignore_list.txt",
                 auto_create: bool = True):
        if auto_create:
            create_if_missing(types_file)
            create_if_missing(ignores_file)
        self._types = TypesList(types_file) if types_file else None
        self._ignores = IgnoresList(ignores_file) if ignores_file else None

    @property
    def types(self) -> Optional[TypesList]:
        return self._types

    @property
    def ignores(self) -> Optional[IgnoresList]:
        return self._ignores

    def is_ignored(self, path: str) -> bool:
        """Decides wether logtype should skip a file or not.

        If the file is in the types database or matches the ignore list,
        it is skipped.
        """
        if self._types and self._types.is_in_database(path):
            raise FoundInTypes
        if self._ignores and self._ignores.is_ignored(path):
            raise IgnoredFile
        return True

    def _try_logtype(self, path: str, logtype: LogType, allow_empty_timestamp: bool = True) -> LogConfig:
        """Can this file be read as logtype?

        If yes return config if no raise LogTypeException. If the file
        is empty, raise LogFileEmpty.
        """

        config = config_factory(path, logtype, datetime_key="time",
                                allow_empty_timestamp=allow_empty_timestamp)
        try:
            # get back first line that parses as logtype
            with Logfile(config, logger=logging.getLogger()) as lf:
                first_line = next(lf, None)
        except UnicodeDecodeError:
            raise LogTypeException(f"Unsupported filetype: {path}")
        except json.decoder.JSONDecodeError:
            raise LogTypeException(f"Not a valid json file: {path}")

        if first_line is None:
            raise LogFileEmpty(f"{path} is empty")
        return config

    def detect_config(self, path: str, allow_empty_timestamp: bool = True) -> LogConfig:
        """Try each log type on the file and return the config of the first one
        that works.

        If none work, raise LogTypeException.
        """

        for logtype in LogType:
            try:
                config = self._try_logtype(path, logtype, allow_empty_timestamp=allow_empty_timestamp)
                return config
            except LogFileEmpty as e:
                raise e
            except DateTimeKeyNotFound as e:
                raise LogTypeException(f"Error in {path}: {e}")
            except LogTypeException:
                continue  # try matching the next LogType
        raise LogTypeException(f"(Unable to determine logtype for: {path}")
