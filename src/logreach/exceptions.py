class LogreachError(Exception):
    """Top-level exception for logreach errors."""


class ParseTimestampError(LogreachError):
    """Exceptions created while parsing the timestamp."""


class NotInRange(LogreachError):
    """Exceptions created if the timestamp is not between begin and end."""


class DateTimeKeyNotFound(LogreachError):
    """Exceptions created if the timestamp can't be found in json-files."""


class DateTimeNotFound(LogreachError):
    """Exceptions created if the timestamp is None."""
