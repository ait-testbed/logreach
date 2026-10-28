class LogreachError(Exception):
    """Base class for errors while reading logfiles."""


class ParseTimestampError(LogreachError):
    """Raised when a timestamp cannot be parsed."""


class NotInRange(LogreachError):
    """Raised when a timestamp is outside the begin/end time window."""


class DateTimeKeyNotFound(LogreachError):
    """Raised when a JSON line has no field with the timestamp key."""


class DateTimeNotFound(LogreachError):
    """Raised when a line has no timestamp and empty timestamps are not
    allowed."""


class LogTypeError(Exception):
    """Base class for errors while detecting the type of a logfile."""


class LogFileEmpty(LogTypeError):
    """Raised when the logfile is empty."""


class SkipFile(Exception):
    """Base class for signals that a file should be skipped."""


class IgnoredFile(SkipFile):
    """Raised when the path matches a pattern in the ignore list."""
