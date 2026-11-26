import json
import zlib


class LogreachError(Exception):
    """Base class for errors while reading logfiles."""


class DateTimeNotFound(LogreachError):
    """Raised when a line has no timestamp and empty timestamps are not
    allowed."""


class NoTimestamp(LogreachError):
    """Raised by parse_timestamp for a line whose timestamp cannot be read; the
    message says why."""


class LogTypeError(LogreachError):
    """Raised when no log type fits a logfile, or it is empty."""


# errors while reading one file: reported at the end, the run goes on with the next file;
# EOFError and zlib.error come from truncated or corrupt gzip files
FILE_ERRORS = (LogreachError, OSError, UnicodeDecodeError, json.JSONDecodeError, EOFError, zlib.error)
