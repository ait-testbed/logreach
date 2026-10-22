import argparse
import logging
import os
import sys
from datetime import datetime
from typing import Any

from dateutil.parser import parse
from rich import print
from rich.console import Console
from rich.logging import RichHandler

from logreach.exceptions import LogreachError
from logreach.logfile import Logfile
from logreach.schemas.logfileconfig import LogConfig
from logreach.schemas.logline import Logline
from logtype.analyzer import DEFAULT_IGNORES_FILE, DEFAULT_TYPES_FILE, Analyzer
from logtype.exceptions import LogFileEmpty, LogTypeError, SkipFile


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


# lines without timestamp reported per file at the end of a run
MAX_REPORTED_LINES = 5


def report_unparsed(path: str, unparsed: list[tuple[int, str]]) -> list[str]:
    """Describe the lines of path that had no timestamp, at most
    MAX_REPORTED_LINES."""
    report = [f'{path}:{lineno}: no timestamp: {line.rstrip()}'
              for lineno, line in unparsed[:MAX_REPORTED_LINES]]
    if len(unparsed) > MAX_REPORTED_LINES:
        report.append(f'{path}: ... and {len(unparsed) - MAX_REPORTED_LINES} more lines without timestamp')
    return report


def eprint(*args: Any, **kwargs: Any) -> None:
    print(*args, file=sys.stderr, **kwargs)


def format_logline(logline: Logline) -> None:
    print(logline)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='logtype',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='Detects the log type of each file in a directory and prints its lines, '
                    'optionally filtered by timestamp')
    parser.add_argument('--path', help='directory with logfiles', required=True)
    #  this does nothing at the moement (ignored etensions)
    parser.add_argument('--ignored-extension', help='comma separated list of ignored file-extensions',
                        default='.gz,.xz,.conf,.journal,.journal~')
    parser.add_argument('--ignorelist-file', help='a file with a list of ignored files. (regex supported)',
                        default=DEFAULT_IGNORES_FILE)
    parser.add_argument('--types-file', help='logtype configuration database', default=DEFAULT_TYPES_FILE)
    parser.add_argument('--begin', help='filter from this timestamp on', type=parsed_datetime)
    parser.add_argument('--end', help='filter logs until this timestamp', type=parsed_datetime)
    parser.add_argument('--force-timestamp', help="Don't allow empty timestamp without stopping",
                        action='store_true')
    args = parser.parse_args()

    logger = setup_logger()

    ignore_empty = True
    problems: list[str] = []  # reported at the end, so a run never stops halfway

    analyzer = Analyzer(types_file=args.types_file, ignores_file=args.ignorelist_file)
    for (root, dirs, files) in os.walk(args.path, followlinks=True):
        for file in files:
            path = os.path.join(root, file)
            try:
                analyzer.check_not_skipped(path)
                config: LogConfig = analyzer.detect_config(
                    path, allow_empty_timestamp=not args.force_timestamp)
                config.begin = args.begin
                config.end = args.end
                with Logfile(config, logger=logger) as lf:
                    for line in lf:
                        format_logline(line)
                problems.extend(report_unparsed(path, lf.unparsed))
            # must come before LogTypeError, which LogFileEmpty subclasses
            except LogFileEmpty:
                if ignore_empty:
                    continue
            except LogreachError as e:
                eprint(f'{path}: {e}')
                sys.exit(1)
            except LogTypeError as e:
                problems.append(str(e))  # no log type fits
                continue
            except SkipFile:
                continue

    if problems:
        # plain stderr instead of rich, which would treat [...] in log lines as markup
        sys.stderr.write('\nProblems found:\n' + ''.join(f'  {problem}\n' for problem in problems))
        sys.exit(1)


if __name__ == '__main__':
    main()
