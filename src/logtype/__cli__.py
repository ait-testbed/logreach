from logtype.exceptions import LogTypeError
from logtype.exceptions import LogFileEmpty
from logreach.logfile import Logfile
from logreach.exceptions import LogreachError
from logreach.schemas.logfileconfig import LogConfig
from logreach.schemas.logline import Logline
import argparse
import logging
import os
import sys
from rich import print
from rich.console import Console
from rich.logging import RichHandler
from logtype.exceptions import SkipFile
from logtype.analyzer import Analyzer
from dateutil.parser import parse
from datetime import datetime
from typing import Any


def setup_logger() -> logging.Logger:
    DATEFMT = "%Y-%m-%dT%H:%M:%SZ"
    FORMAT = "%(message)s"
    if sys.stderr.isatty():
        handler = RichHandler(console=Console(stderr=True))
        FORMAT = "%(message)s"
    else:
        FORMAT = "%(asctime)s\t%(levelname)s\t%(message)s"
        handler = logging.StreamHandler()

    logging.basicConfig(
        level="NOTSET", format=FORMAT, datefmt=DATEFMT, handlers=[handler]
    )

    logger = logging.getLogger(__name__)
    return logger


def parsed_datetime(datetime_str: str) -> datetime:
    return parse(datetime_str, fuzzy=True)


def eprint(*args: Any, **kwargs: Any) -> None:
    print(*args, file=sys.stderr, **kwargs)


def format_logline(logline: Logline) -> None:
    print(logline)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='analyze_logfiles',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='detects non-syslog logfiles in a directory')
    parser.add_argument('--path', help='directory with logfiles', required=True)
    parser.add_argument('--ignored-extension', help='comma seperated list of ignored file-extensions',
                        default=".gz,.xz,.conf,.journal,.journal~")
    parser.add_argument('--ignorelist-file', help="a file with a list of ignored files. (regex supported)",
                        required=False, default="ignore_list.txt")
    parser.add_argument('--types-file', help="logtype configuration database",
                        required=False, default="logtypes.json")
    parser.add_argument('--begin', help='filter from this timestamp on', required=False, type=parsed_datetime)
    parser.add_argument('--end', help='filter logs until this timestamp',
                        required=False, type=parsed_datetime)
    parser.add_argument('--force-timestamp', help="Don't allow empty timestamp without stopping",
                        action="store_true", default=False)
    args = parser.parse_args()

    logger = setup_logger()

    ignore_empty = True

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
            # must come before LogTypeError, which LogFileEmpty subclasses
            except LogFileEmpty:
                if ignore_empty:
                    continue
            except LogreachError as e:
                eprint(f"{path}: {e}")
                exit(1)
            except LogTypeError as e:
                eprint(e)
                exit(1)
            except SkipFile:
                continue


if __name__ == "__main__":
    main()
