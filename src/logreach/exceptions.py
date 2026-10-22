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
