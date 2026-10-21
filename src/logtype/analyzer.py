from logtype.exceptions import FoundInTypes, IgnoredFile, LogTypeException, LogFileEmpty
from logreach.exceptions import DateTimeKeyNotFound
from logreach.schemas.logfileconfig import LogType, LogConfig
from logreach.logfile import config_factory, Logfile
import logging
import json
import re
import os
from typing import Any, Optional


class IgnoresList:
    def __init__(self, ignorelist_file: str):
        self.ignorelist_file = ignorelist_file
        self.patterns: list[re.Pattern[str]] = []
        self.compile_regex()

    def compile_regex(self) -> None:
        with open(self.ignorelist_file, 'r') as list_file:
            for line in list_file:
                self.patterns.append(re.compile(line.rstrip('\n')))

    def is_ignored(self, filepath: str) -> bool:
        for pattern in self.patterns:
            if re.search(pattern, filepath):
                return True
        return False


class TypesList:
    def __init__(self, types_file: str = "logtypes.json"):
        self.file = types_file
        self.data: dict[str, dict[str, Any]] = {}
        self._read_file()

    def _read_file(self) -> None:
        with open(self.file, 'r') as types_file:
            for line in types_file:
                item = json.loads(line)
                self.data[item["logfile_path"]] = item

    def is_in_database(self, path: str) -> bool:
        if path in self.data.keys():
            return True
        return False


class Analyzer:
    def __init__(self, types_file: str = "logtypes.json", ignores_file: str = "ignore_list.txt",
                 auto_create: bool = True):
        self._types = None
        self._ignores = None
        if types_file:
            if auto_create:
                if not os.path.exists(types_file):
                    with open(types_file, 'w'):
                        pass
            self._types = TypesList(types_file)
        if ignores_file:
            if auto_create:
                if not os.path.exists(ignores_file):
                    with open(ignores_file, 'w'):
                        pass
            self._ignores = IgnoresList(ignores_file)

    @property
    def types(self) -> Optional[TypesList]:
        return self._types

    @property
    def ignores(self) -> Optional[IgnoresList]:
        return self._ignores

    def is_ignored(self, full_path: str) -> bool:
        if self._types:
            if self._types.is_in_database(full_path):
                raise FoundInTypes
        if self._ignores:
            if self._ignores.is_ignored(full_path):
                raise IgnoredFile
        return True

    def check_type(self, path: str, logtype: LogType, allow_empty_timestamp: bool = True) -> LogConfig:
        datetimekey: str = "time"
        config: LogConfig = config_factory(
            path, logtype, datetimekey=datetimekey, allow_empty_timestamp=allow_empty_timestamp)
        try:
            first_line = None
            with Logfile(config, logger=logging.getLogger()) as lf:
                for line in lf:
                    first_line = line
                    break
            if first_line is None:
                raise LogFileEmpty(f"{path} is empty")
            if first_line.timestamp is None:
                raise LogTypeException(f"Unable to determine timestamp in {path}: {first_line}")
        except UnicodeDecodeError:
            raise LogTypeException(f"Unsupported filetype: {path}")
        except json.decoder.JSONDecodeError:
            raise LogTypeException(f"Not a valid json file: {path}")
        return config

    def determine(self, full_path: str, allow_empty_timestamp: bool = True) -> LogConfig:
        for logtype in LogType:
            try:
                config = self.check_type(full_path, logtype, allow_empty_timestamp=allow_empty_timestamp)
                return config
            except LogFileEmpty as e:
                raise e
            except DateTimeKeyNotFound as e:
                raise LogTypeException(f"Error in {full_path}: {e}")
            except LogTypeException:
                continue
        raise LogTypeException(f"(Unable to determine logtype for: {full_path}")
