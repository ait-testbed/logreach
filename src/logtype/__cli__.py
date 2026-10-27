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


def report_unparsed(path: str, lf: Logfile) -> list[str]:
    """Describe the lines of path that had no timestamp: the ones Logfile
    kept, plus a count of the rest."""
    report = [f'{path}:{lineno}: no timestamp: {line.rstrip()}' for lineno, line in lf.unparsed]
    if lf.unparsed_count > len(lf.unparsed):
        report.append(f'{path}: ... and {lf.unparsed_count - len(lf.unparsed)} more lines without timestamp')
    return report


def exit_with_report(problems: list[str], max_problems: int, unparsed_lines: int,
                     undetermined_files: int) -> None:
    """List at most max_problems problems on stderr, count the rest, and exit
    with code 1."""
    shown = problems[:max_problems]
    report = ['', 'Problems found:', *(f'  {problem}' for problem in shown)]
    if len(problems) > len(shown):
        report.append(f'  ... and {len(problems) - len(shown)} more (see --max-problems)')
    report.append(f'{unparsed_lines} lines without timestamp, {undetermined_files} undetermined files')
    sys.stdout.flush()  # so the report comes after all output, even when stdout is redirected
    # plain stderr instead of rich, which would treat [...] in log lines as markup
    sys.stderr.write('\n'.join(report) + '\n')
    sys.exit(1)


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
    parser.add_argument('--max-problems', type=int, default=50,
                        help='problems listed at the end of the run; the rest are only counted')
    parser.add_argument('--fail-fast', action='store_true',
                        help='stop at the first problem instead of reporting all problems at the end')
    parser.add_argument('--check', action='store_true',
                        help="show each file's detected type instead of its lines, to find problems fast")
    args = parser.parse_args()

    logger = setup_logger()

    ignore_empty = True
    problems: list[str] = []  # reported at the end, so a run never stops halfway
    unparsed_lines = 0
    undetermined_files = 0

    analyzer = Analyzer(types_file=args.types_file, ignores_file=args.ignorelist_file)
    for (root, dirs, files) in os.walk(args.path, followlinks=True):
        for file in files:
            if args.fail_fast and problems:  # fail early
                exit_with_report(problems, args.max_problems, unparsed_lines, undetermined_files)
            path = os.path.join(root, file)
            try:
                analyzer.check_not_skipped(path)
                config: LogConfig = analyzer.detect_config(
                    path, allow_empty_timestamp=not args.force_timestamp)
                config.begin = args.begin
                config.end = args.end
                if args.check:
                    # plain stdout instead of rich, which would wrap long paths
                    sys.stdout.write(f'{path}: {config.describe()}\n')
                with Logfile(config, logger=logger) as lf:
                    for line in lf:
                        # checked before printing: reading this line may have skipped one without timestamp
                        if args.fail_fast and lf.unparsed_count:
                            break
                        if not args.check:
                            format_logline(line)
                problems.extend(report_unparsed(path, lf))
                unparsed_lines += lf.unparsed_count
            # must come before LogTypeError, which LogFileEmpty subclasses
            except LogFileEmpty:
                if ignore_empty:
                    continue
            except LogreachError as e:
                eprint(f'{path}: {e}')
                sys.exit(1)
            except LogTypeError as e:
                problems.append(str(e))  # no log type fits
                undetermined_files += 1
                continue
            except SkipFile:
                continue

    if problems:
        exit_with_report(problems, args.max_problems, unparsed_lines, undetermined_files)


if __name__ == '__main__':
    main()
