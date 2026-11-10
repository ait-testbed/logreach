import argparse
import logging
import os
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import NoReturn
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dateutil.parser import parse
from rich import print
from rich.console import Console
from rich.logging import RichHandler

from logreach.analyzer import DEFAULT_IGNORES_FILE, DEFAULT_TYPES_FILE, Analyzer
from logreach.exceptions import FILE_ERRORS, LogreachError, LogTypeError
from logreach.interactive import Answer, ask_and_save_logtype
from logreach.logfile import Logfile, config_factory
from logreach.schemas.logfileconfig import LogConfig, LogType
from logreach.schemas.logline import Logline


def setup_logger() -> logging.Logger:
    DATEFMT = '%Y-%m-%dT%H:%M:%SZ'
    FORMAT = '%(message)s'
    if sys.stderr.isatty():
        handler = RichHandler(console=Console(stderr=True))
        FORMAT = '%(message)s'
    else:
        FORMAT = '%(asctime)s\t%(levelname)s\t%(message)s'
        handler = logging.StreamHandler()

    logging.basicConfig(
        level='NOTSET', format=FORMAT, datefmt=DATEFMT, handlers=[handler]
    )

    logger = logging.getLogger(__name__)
    return logger


def parsed_datetime(datetime_str: str) -> datetime:
    return parse(datetime_str, fuzzy=True)


def parsed_timezone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise argparse.ArgumentTypeError(f'unknown timezone: {name}')


def print_logline(logline: Logline) -> None:
    print(logline)


# def print_logline_with_timestamp(logline: Logline) -> None:
#     """Not used yet: can replace print_logline to make output sortable for
#     example."""
#     print(f'{logline.timestamp.isoformat()} {logline.filename}:{logline.lineno}:'
#           f'{logline.raw.rstrip("\r\n")}\n')


# characters of a log line shown in the problem report; the line number leads to the rest
MAX_SHOWN_CHARS = 200


def shortened(text: str) -> str:
    return text if len(text) <= MAX_SHOWN_CHARS else text[:MAX_SHOWN_CHARS] + '…'


@dataclass
class Problems:
    """Problems collected during the run, reported at the end so a run never
    stops halfway."""

    messages: list[str] = field(default_factory=list)
    unparsed_lines: int = 0
    undetermined_files: int = 0
    failed_files: int = 0

    def add_unparsed(self, path: str, logfile: Logfile) -> None:
        """Add the lines of path that had no timestamp: the ones Logfile kept,
        plus a count of the rest."""
        self.messages.extend(f'{path}:{lineno}: {reason}: {shortened(line.rstrip())}'
                             for lineno, reason, line in logfile.unparsed)
        not_kept = logfile.unparsed_count - len(logfile.unparsed)
        if not_kept:
            self.messages.append(f'{path}: ... and {not_kept} more lines without timestamp')
        self.unparsed_lines += logfile.unparsed_count

    def add_undetermined(self, message: str) -> None:
        self.messages.append(message)
        self.undetermined_files += 1

    def add_failed(self, path: str, error: Exception) -> None:
        self.messages.append(f'{path}: {error}')
        self.failed_files += 1

    def exit_with_report(self, max_problems: int) -> NoReturn:
        """List at most max_problems problems on stderr, count the rest, and
        exit with code 1."""
        shown = self.messages[:max_problems]
        report = ['', 'Problems found:', *(f'  {problem}' for problem in shown)]
        if len(self.messages) > len(shown):
            report.append(f'  ... and {len(self.messages) - len(shown)} more (see --max-problems)')
        report.append(f'{self.unparsed_lines} lines without timestamp, '
                      f'{self.undetermined_files} undetermined files, {self.failed_files} files with errors')
        sys.stdout.flush()  # so the report comes after all output, even when stdout is redirected
        # plain stderr instead of rich, which would treat [...] in log lines as markup
        sys.stderr.write('\n'.join(report) + '\n')
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='logreach',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='Detects the log type of a logfile, or of each file in a directory, and prints its '
                    'lines, optionally filtered by timestamp')
    parser.add_argument('path', help='logfile or directory with logfiles')
    parser.add_argument('--type', choices=[t.value for t in LogType],
                        help='read every file as this type instead of detecting it')
    parser.add_argument('--datetimekey', help='timestamp key for --type json')
    parser.add_argument('--datetimeregex',
                        help='regex whose first group is the timestamp, for --type syslog, audit or access')
    parser.add_argument('--dayfirst', action='store_true',
                        help='read ambiguous dates like 1/9/2026 as day/month (1 September)')
    parser.add_argument('--begin', help='filter from this timestamp on', type=parsed_datetime)
    parser.add_argument('--end', help='filter logs until this timestamp', type=parsed_datetime)
    parser.add_argument('--grep', action='append', metavar='REGEX',
                        help='print only lines matching this regex; repeat it to print lines matching any')
    parser.add_argument('--ignore-case', action='store_true', help='--grep ignores upper and lower case')
    parser.add_argument('--timezone', default='UTC', type=parsed_timezone,
                        help='timezone of timestamps without one, in the logs and in --begin / --end, '
                             'e.g. Europe/Vienna; a "timezone" in the types file overrides it per file')
    parser.add_argument('--ignored-extension', default='.gz,.xz,.conf,.journal,.journal~',
                        help="comma separated list of file extensions ignored in directories, '' for none")
    parser.add_argument('--ignorelist-file', default=DEFAULT_IGNORES_FILE,
                        help='file with one regex per line; matching paths in directories are ignored')
    parser.add_argument('--types-file', help='logtype configuration database', default=DEFAULT_TYPES_FILE)
    parser.add_argument('--require-timestamp', action='store_true',
                        help='treat a line without a timestamp as an error that stops reading the file')
    parser.add_argument('--max-problems', type=int, default=50,
                        help='problems listed at the end of the run; the rest are only counted')
    parser.add_argument('--fail-fast', action='store_true',
                        help='stop at the first problem instead of reporting all problems at the end')
    parser.add_argument('--check', action='store_true',
                        help="show each file's detected type instead of its lines, to find problems fast")
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='with --check: ask for the type of each file whose type is not detected, '
                             'and save the answer in --types-file')
    args = parser.parse_args()

    if args.type == LogType.JSON.value and not args.datetimekey:
        parser.error('--type json requires --datetimekey')
    if (args.datetimekey or args.datetimeregex) and not args.type:
        parser.error('--datetimekey and --datetimeregex require --type')
    if not os.path.exists(args.path):
        parser.error(f'{args.path} does not exist')
    if args.interactive:
        if not args.check:
            parser.error('--interactive requires --check')
        if not args.types_file:
            parser.error('--interactive requires a --types-file to save the answers in')
        if not sys.stdin.isatty():
            parser.error('--interactive needs a terminal to ask questions')
    if args.grep:
        flags = re.IGNORECASE if args.ignore_case else 0
        try:
            args.grep = [re.compile(pattern, flags) for pattern in args.grep]
        except re.error as e:
            parser.error(f'invalid --grep regex {e.pattern!r}: {e}')
        if args.check:
            sys.stderr.write('--grep is ignored with --check\n')
    # --begin / --end without timezone are meant in --timezone, for every file
    if args.begin and args.begin.tzinfo is None:
        args.begin = args.begin.replace(tzinfo=args.timezone)
    if args.end and args.end.tzinfo is None:
        args.end = args.end.replace(tzinfo=args.timezone)
    return args


def iter_logfiles(path: str, analyzer: Analyzer) -> Iterator[tuple[str, str | None]]:
    """Yield (file, why it is ignored or None): path itself if it is a file,
    else every file below it."""
    if not os.path.isdir(path):
        yield path, None  # named explicitly, so the ignore list does not apply
        return
    for root, _dirs, files in os.walk(path, followlinks=True):
        for file in files:
            filepath = os.path.join(root, file)
            yield filepath, analyzer.ignores.ignore_reason(filepath)


def make_config(path: str, args: argparse.Namespace, analyzer: Analyzer) -> LogConfig:
    """Build the config from --type, else from the types file or detection.

    Raises LogTypeError if no log type fits.
    """
    allow_empty_timestamp = not args.require_timestamp
    if args.type:
        return config_factory(path, LogType(args.type), allow_empty_timestamp=allow_empty_timestamp,
                              datetime_key=args.datetimekey, datetime_regex=args.datetimeregex,
                              begin=args.begin, end=args.end, dayfirst=args.dayfirst, timezone=args.timezone)
    return analyzer.detect_config(path, allow_empty_timestamp=allow_empty_timestamp, begin=args.begin,
                                  end=args.end, dayfirst=args.dayfirst, timezone=args.timezone)


def process_file(path: str, ignored: str | None, args: argparse.Namespace, analyzer: Analyzer,
                 logger: logging.Logger, problems: Problems) -> None:
    """Print the lines of one logfile (or only its type with --check) and
    collect its problems.

    Ignored and empty files are skipped; --check shows why.
    """
    skip_reason = None
    if ignored:
        skip_reason = f'ignored: {ignored}'
    elif os.path.getsize(path) == 0:
        skip_reason = 'empty'
    if skip_reason:
        if args.check:
            sys.stdout.write(f'{path}: skipped ({skip_reason})\n')
        return  # skipped files are no problems

    try:
        config = make_config(path, args, analyzer)
    except LogTypeError as e:
        answer = ask_and_save_logtype(path, e, analyzer) if args.interactive else Answer.SKIPPED
        if answer == Answer.SKIPPED:
            problems.add_undetermined(str(e))
            return
        if answer == Answer.IGNORED:
            return process_file(path, analyzer.ignores.ignore_reason(path), args, analyzer, logger, problems)
        config = make_config(path, args, analyzer)  # now from the types file

    if args.check:
        # plain stdout instead of rich, which would wrap long paths
        sys.stdout.write(f'{path}: {config.describe()}\n')
    with Logfile(config, logger=logger) as logfile:
        try:
            for line in logfile:
                # checked before printing: reading this line may have skipped one without timestamp
                if args.fail_fast and logfile.unparsed_count:
                    break
                if args.grep and not any(pattern.search(line.raw) for pattern in args.grep):
                    continue
                if not args.check:
                    print_logline(line)
        finally:
            problems.add_unparsed(path, logfile)


def main() -> None:
    args = parse_args()
    logger = setup_logger()
    ignored_extensions = [extension.strip() for extension in args.ignored_extension.split(',')
                          if extension.strip()]
    try:
        analyzer = Analyzer(types_file=args.types_file, ignores_file=args.ignorelist_file,
                            ignored_extensions=ignored_extensions)
    except LogreachError as e:  # a broken types file: nothing can be read right, so stop before reading
        sys.stderr.write(f'logreach: {e}\n')
        sys.exit(2)
    problems = Problems()

    try:
        for path, ignored in iter_logfiles(args.path, analyzer):
            try:
                process_file(path, ignored, args, analyzer, logger, problems)
            except FILE_ERRORS as e:
                problems.add_failed(path, e)
            if args.fail_fast and problems.messages:
                break
    except KeyboardInterrupt:
        sys.exit(1)

    if problems.messages:
        problems.exit_with_report(args.max_problems)


if __name__ == '__main__':
    main()
