"""--check --interactive: ask for the type of files that are not detected
and save the answers in the types file."""

import json
import logging
import re
from enum import Enum
from itertools import islice
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.text import Text

from logreach.analyzer import Analyzer
from logreach.exceptions import FILE_ERRORS, LogTypeError
from logreach.logfile import DEFAULT_TIMESTAMP_REGEX, Logfile, config_factory
from logreach.schemas.logfileconfig import LogType


class Answer(Enum):
    """What ask_and_save_logtype() did with a file."""

    SAVED = 'saved'  # type saved in the types file
    IGNORED = 'ignored'  # path added to the ignore list
    SKIPPED = 'skipped'  # left undetermined


SAMPLE_LINES = 5  # lines of the file shown before asking
PREVIEW_LINES = 3  # parsed lines shown before saving


def ask_timestamp_location(path: str, logtype: LogType, console: Console) -> dict[str, str] | None:
    """Ask how timestamps are found in path: the json key or the regex.

    Returns the types file entry, or None if the answer does not work.
    """
    entry = {'logfile_path': path, 'type': logtype.value}
    if logtype == LogType.JSON:
        try:
            with open(path) as logfile:
                record = json.loads(logfile.readline())
        except (json.JSONDecodeError, UnicodeDecodeError):
            console.print('The first line is no JSON object.')
            return None
        if not isinstance(record, dict) or not record:
            console.print('The first line is no JSON object with keys.')
            return None
        entry['datetimekey'] = Prompt.ask('Key of the timestamp', choices=list(record), console=console)
        return entry

    default = DEFAULT_TIMESTAMP_REGEX[logtype].value
    regex = Prompt.ask('Regex whose first group is the timestamp', default=default, console=console)
    try:
        groups = re.compile(regex).groups
    except re.error as e:
        console.print(f'Invalid regex: {e}')
        return None
    if not groups:
        console.print('The regex needs a group (...) around the timestamp.')
        return None
    if regex != default:
        entry['datetimeregex'] = regex
    return entry


def ask_timezone(console: Console) -> str | None:
    """Ask for the timezone of timestamps without one; None keeps
    --timezone."""
    while True:
        name: str = Prompt.ask('Timezone of these timestamps (empty: --timezone)',
                               default='', console=console)
        if not name:
            return None
        try:
            ZoneInfo(name)
            return name
        except (ZoneInfoNotFoundError, ValueError):
            console.print(f'Unknown timezone: {name}')


def ask_and_save_logtype(path: str, error: LogTypeError, analyzer: Analyzer) -> Answer:
    """Show the start of path and ask for its type until the answer reads
    timestamps, then save it in the types file.

    Returns what was done with the file.
    """
    types = analyzer.types
    assert types is not None, '--interactive requires a types file'
    # stderr: stdout keeps only the --check lines; no markup or emoji: log lines and paths show as they are
    console = Console(stderr=True, markup=False, highlight=False, emoji=False)
    console.print(f'\n{error}')
    with open(path, errors='replace') as logfile:
        for lineno, line in enumerate(islice(logfile, SAMPLE_LINES), 1):
            console.print(f'  {lineno} | {line.rstrip()}')

    choices = [logtype.value for logtype in LogType]
    if analyzer.ignores.ignores_file:
        choices.append('ignore')
    try:
        while True:
            choice = Prompt.ask('Log type', choices=[*choices, 'skip'], default='skip', console=console)
            if choice == 'skip':
                return Answer.SKIPPED
            if choice == 'ignore':
                analyzer.ignores.add(re.escape(path) + r'\Z')
                return Answer.IGNORED

            logtype = LogType(choice)
            entry = ask_timestamp_location(path, logtype, console)
            if entry is None:
                continue
            config = config_factory(path, logtype, datetime_key=entry.get('datetimekey'),
                                    datetime_regex=entry.get('datetimeregex'))
            try:
                with Logfile(config, logger=logging.getLogger()) as logfile:
                    lines = list(islice(logfile, PREVIEW_LINES))
            except FILE_ERRORS as e:
                console.print(f'Cannot read {path} as {logtype.value}: {e}')
                continue
            if not lines:
                console.print(f'No line has a timestamp when read as {logtype.value}.')
                continue
            for line in lines:
                console.print(f'  line {line.lineno} -> {line.timestamp.isoformat()}')
            # Logfile attached UTC; ask only if the file's timestamps have no timezone of their own
            if config.parse_timestamp(lines[0].raw).tzinfo is None:
                timezone_name = ask_timezone(console)
                if timezone_name:
                    entry['timezone'] = timezone_name
            if Confirm.ask(Text(f'Save in {types.types_file}?'), default=True, console=console):
                types.add(entry)
                return Answer.SAVED
    except EOFError:  # input closed: leave this file undetermined
        return Answer.SKIPPED
