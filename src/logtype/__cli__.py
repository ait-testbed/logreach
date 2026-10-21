from logtype.exceptions import LogTypeException
from logtype.exceptions import LogFileEmpty
from logmate.logfile import Logfile
from logmate.exceptions import LogmateError
from logmate.schemas.logfileconfig import LogConfig
import argparse
import logging
import os
import sys
from rich import print
from rich.console import Console
from rich.logging import RichHandler
from logtype.exceptions import Ignores
from logtype.analyzer import Analyzer
from dateutil.parser import parse
from datetime import datetime

def setup_logger():
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

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def format_logline(logline:Logline):
    print(logline)

def main():
    parser = argparse.ArgumentParser(
                    prog='analyze_logfiles',
                    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                    description='detects non-syslog logfiles in a directory')
    parser.add_argument('--path', help='directory with logfiles', required=True)
    parser.add_argument('--ignored-extension', help='comma seperated list of ignored file-extensions', default=".gz,.xz,.conf,.journal,.journal~")
    parser.add_argument('--ignorelist-file', help="a file with a list of ignored files. (regex supported)", required=False, default="ignore_list.txt")
    parser.add_argument('--types-file', help="logtype configuration database", required=False, default="logtypes.json")
    parser.add_argument('--begin', help='filter from this timestamp on', required=False, type=parsed_datetime)
    parser.add_argument('--end', help='filter logs until this timestamp', required=False, type=parsed_datetime)
    parser.add_argument('--force-timestamp', help="Don't allow empty timestamp without stopping", action="store_true", default=False)
    args = parser.parse_args()

    logger = setup_logger()

    ignore_empty = True

    scanner = Analyzer(types_file=args.types_file, ignores_file=args.ignorelist_file)
    for (root,dirs,files) in os.walk(args.path, followlinks=True):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                scanner.is_ignored(full_path)
                config: LogConfig = scanner.determine(full_path, allow_empty_timestamp=not args.force_timestamp)
                config.begin = args.begin
                config.end = args.end
                with Logfile(config, logger=logger) as lf:
                    for line in lf:
                        format_logline(line)
            except LogFileEmpty:
                if ignore_empty:
                    continue
            except LogmateError as e:
                eprint(f"{full_path}: {e}")
                exit(1)
            except LogTypeException as e:
                eprint(e)
                exit(1)
            except Ignores:
                continue




if __name__ == "__main__":
    main()
