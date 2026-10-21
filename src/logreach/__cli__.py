from logreach.logfile import Logfile,config_factory
from logreach.schemas.logline import Logline
from logreach.schemas.logfileconfig import LogType
from dateutil.parser import parse
from datetime import datetime
from rich import print
from rich.console import Console
from rich.logging import RichHandler
import argparse
import sys
import logging

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

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def parsed_datetime(datetime_str: str) -> datetime:
    return parse(datetime_str, fuzzy=True)

def format_logline(logline:Logline):
    print(logline)

def main():
    parser = argparse.ArgumentParser(
                    prog='logreach',
                    description='Filters logfiles by extracting and comparing timestamps')
    parser.add_argument('--file', help='path to logfile', required=True)
    parser.add_argument('--begin', help='filter from this timestamp on', required=False, type=parsed_datetime)
    parser.add_argument('--end', help='filter logs until this timestamp', required=False, type=parsed_datetime)
    parser.add_argument('--datetimekey', help='datetimekey in json-log')
    parser.add_argument('--datetimeregex', help="Regex with matching groups to find the datetime", required=False)
    parser.add_argument('--type', choices=['syslog', 'audit', 'json', 'access'], default='syslog')

    args = parser.parse_args()

    logger: logging.Logger = setup_logger()

    config = config_factory(args.file, LogType(args.type), datetimekey=args.datetimekey, datetimeregex=args.datetimeregex, begin=args.begin, end=args.end)

    try:
        with Logfile(config, logger=logger) as lf:
            for line in lf:
                format_logline(line)
    except KeyboardInterrupt:
        sys.exit(1)
    except (FileNotFoundError, PermissionError) as e:
        eprint(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
