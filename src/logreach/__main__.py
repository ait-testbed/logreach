import argparse
import os
import re
import sys
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dateutil.parser import ParserError, parse
from rich import print

from logreach.analyzer import DEFAULT_IGNORES_FILE, DEFAULT_TYPES_FILE, Analyzer
from logreach.api import FileEvent, FileStatus, Logreach, Problems
from logreach.exceptions import LogreachError, LogTypeError
from logreach.interactive import Answer, ask_and_save_logtype
from logreach.schemas.logfileconfig import LogType
from logreach.schemas.logline import Logline


def parsed_datetime(datetime_str: str) -> datetime:
    try:
        return parse(datetime_str, fuzzy=True)
    except (ParserError, OverflowError):
        raise argparse.ArgumentTypeError(f'not a date: {datetime_str}')


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


def problem_report(problems: Problems, max_problems: int) -> str:
    """List at most max_problems problems and count the rest."""
    shown = problems.messages[:max_problems]
    report = ['', 'Problems found:', *(f'  {problem}' for problem in shown)]
    if len(problems.messages) > len(shown):
        report.append(f'  ... and {len(problems.messages) - len(shown)} more (see --max-problems)')
    report.append(f'{problems.unparsed_lines} lines without timestamp, '
                  f'{problems.undetermined_files} undetermined files, '
                  f'{problems.failed_files} files with errors')
    return '\n'.join(report) + '\n'


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='logreach',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='Detects the log type of a logfile, or of each file in a directory, and prints its '
                    'lines, optionally filtered by timestamp')
    parser.add_argument('path', help='logfile or directory with logfiles')
    parser.add_argument('--type', choices=[t.value for t in LogType],
                        help='read every file as this type instead of detecting it')
    parser.add_argument('--datetime-key', help='timestamp key for --type json')
    parser.add_argument('--datetime-regex',
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
    parser.add_argument('--ignored-extensions', default='.gz,.xz,.conf,.journal,.journal~',
                        help="comma separated list of file extensions ignored in directories, '' for none")
    parser.add_argument('--ignore-file', default=DEFAULT_IGNORES_FILE,
                        help='file with one regex per line; matching paths in directories are ignored')
    parser.add_argument('--types-file', help='logtype configuration database', default=DEFAULT_TYPES_FILE)
    parser.add_argument('--require-timestamp', action='store_true',
                        help='treat a line without a timestamp as an error that stops reading the file')
    parser.add_argument('--max-problems', type=int, default=50,
                        help='problems listed at the end of the run; the rest are only counted')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='do not list the problems at the end; the exit code still shows them')
    parser.add_argument('--fail-fast', action='store_true',
                        help='stop at the first problem instead of reporting all problems at the end')
    parser.add_argument('--check', action='store_true',
                        help="show each file's detected type instead of its lines, to find problems fast")
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='with --check: ask for the type of each file whose type is not detected, '
                             'and save the answer in --types-file')
    # old spellings, hidden from --help so scripts using them keep working
    for old, dest in (('--datetimekey', 'datetime_key'), ('--datetimeregex', 'datetime_regex'),
                      ('--ignored-extension', 'ignored_extensions'), ('--ignorelist-file', 'ignore_file')):
        parser.add_argument(old, dest=dest, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    args = parser.parse_args()

    # also checked by Logreach, here with the flag names
    if args.type == LogType.JSON.value and not args.datetime_key:
        parser.error('--type json requires --datetime-key')
    if (args.datetime_key or args.datetime_regex) and not args.type:
        parser.error('--datetime-key and --datetime-regex require --type')
    regexes = [('--datetime-regex', args.datetime_regex), *(('--grep', p) for p in args.grep or ())]
    for option, pattern in regexes:
        try:
            re.compile(pattern or '')
        except re.error as e:
            parser.error(f'invalid {option} regex {pattern!r}: {e}')
    if not os.path.exists(args.path):
        parser.error(f'{args.path} does not exist')
    if args.interactive:
        if args.quiet:
            parser.error('--interactive cannot be combined with --quiet')
        if not args.check:
            parser.error('--interactive requires --check')
        if not args.types_file:
            parser.error('--interactive requires a --types-file to save the answers in')
        if not sys.stdin.isatty():
            parser.error('--interactive needs a terminal to ask questions')
    if args.grep and args.check and not args.quiet:
        sys.stderr.write('--grep is ignored with --check\n')
    return args


def ask_logtype(path: str, error: LogTypeError, analyzer: Analyzer) -> bool:
    """--interactive: True if the answer was saved, so the file is looked at again."""
    return bool(ask_and_save_logtype(path, error, analyzer) != Answer.SKIPPED)


def main() -> None:
    args = parse_args()
    ignored_extensions = [extension.strip() for extension in args.ignored_extensions.split(',')
                          if extension.strip()]
    try:
        logreach = Logreach(logtype=args.type, datetime_key=args.datetime_key,
                            datetime_regex=args.datetime_regex, dayfirst=args.dayfirst,
                            timezone=args.timezone, begin=args.begin, end=args.end, grep=args.grep or (),
                            ignore_case=args.ignore_case, require_timestamp=args.require_timestamp,
                            fail_fast=args.fail_fast, types_file=args.types_file,
                            ignores_file=args.ignore_file, ignored_extensions=ignored_extensions,
                            on_undetermined=ask_logtype if args.interactive else None)
    except LogreachError as e:  # a broken types file: nothing can be read right, so stop before reading
        sys.stderr.write(f'logreach: {e}\n')
        sys.exit(2)

    try:
        for item in logreach.read(args.path):
            if isinstance(item, FileEvent):
                # plain stdout instead of rich, which would wrap long paths
                if args.check and item.status == FileStatus.READ:
                    sys.stdout.write(f'{item.path}: {item.message}\n')
                elif args.check and item.status == FileStatus.SKIPPED:
                    sys.stdout.write(f'{item.path}: skipped ({item.message})\n')
            elif not args.check and item.timestamp is not None:  # lines without timestamp are reported
                print_logline(item)
    except KeyboardInterrupt:
        sys.exit(1)

    if logreach.problems.messages:
        if not args.quiet:
            sys.stdout.flush()  # so the report comes after all output, even when stdout is redirected
            # plain stderr instead of rich, which would treat [...] in log lines as markup
            sys.stderr.write(problem_report(logreach.problems, args.max_problems))
        sys.exit(1)


if __name__ == '__main__':
    main()
