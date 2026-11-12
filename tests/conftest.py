"""Fixtures shared by the tests: files in tmp_path and running the CLI."""

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import logreach.__cli__ as cli
from logreach.schemas.logline import Logline


@pytest.fixture
def make_logs(tmp_path: Path) -> Callable[[dict[str, str | bytes]], Path]:
    """make_logs({name: content}) creates the files in tmp_path/logs and
    returns that directory."""

    def make(files: dict[str, str | bytes]) -> Path:
        logs = tmp_path / 'logs'
        logs.mkdir(exist_ok=True)
        for name, content in files.items():
            if isinstance(content, bytes):
                (logs / name).write_bytes(content)
            else:
                (logs / name).write_text(content)
        return logs
    return make


@pytest.fixture
def types_file(tmp_path: Path) -> Callable[..., Path]:
    """types_file(entry, ...) writes the entries to tmp_path/logtypes.json, the
    types file run_logreach uses, and returns its path."""

    def write(*entries: dict[str, Any]) -> Path:
        path = tmp_path / 'logtypes.json'
        path.write_text(''.join(json.dumps(entry) + '\n' for entry in entries))
        return path
    return write


@pytest.fixture
def ignore_list(tmp_path: Path) -> Callable[..., Path]:
    """ignore_list(line, ...) writes the lines to tmp_path/ignore_list.txt, the
    ignore list run_logreach uses, and returns its path."""

    def write(*lines: str) -> Path:
        path = tmp_path / 'ignore_list.txt'
        path.write_text(''.join(line + '\n' for line in lines))
        return path
    return write


@pytest.fixture
def run_logreach(monkeypatch: pytest.MonkeyPatch,
                 tmp_path: Path) -> Callable[..., tuple[list[Logline], int | str | None]]:
    """run_logreach(path, *args) runs the CLI with the types file and ignore
    list in tmp_path, and returns the lines it would print and its exit
    code."""

    def run(path: Path, *args: str) -> tuple[list[Logline], int | str | None]:
        printed: list[Logline] = []
        monkeypatch.setattr(cli, 'print_logline', printed.append)
        monkeypatch.setattr(sys, 'argv', [
            'logreach', str(path),
            '--ignorelist-file', str(tmp_path / 'ignore_list.txt'),
            '--types-file', str(tmp_path / 'logtypes.json'),
            *args])
        try:
            cli.main()
        except SystemExit as e:
            return printed, e.code
        return printed, 0
    return run
