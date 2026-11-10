import json


class LogreachError(Exception):
    """Base class for errors while reading logfiles."""


class DateTimeKeyNotFound(LogreachError):
    """Raised when a JSON line has no field with the timestamp key."""


class DateTimeNotFound(LogreachError):
    """Raised when a line has no timestamp and empty timestamps are not
    allowed."""


class LogTypeError(Exception):
    """Raised when no log type fits a logfile, or it is empty."""


# errors while reading one file: reported at the end, the run goes on with the next file
FILE_ERRORS = (LogreachError, OSError, UnicodeDecodeError, json.JSONDecodeError)
