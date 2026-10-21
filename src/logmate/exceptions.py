class LogmateError(Exception):
    """Top-level exception for logmate errors."""

class ParseTimestampError(LogmateError):
    """Exceptions created while parsing the timestamp."""

class NotInRange(LogmateError):
    """Exceptions created if the timestamp is not between begin and end"""

class DateTimeKeyNotFound(LogmateError):
    """Exceptions created if the timestamp can't be found in json-files"""

class DateTimeNotFound(LogmateError):
    """Exceptions created if the timestamp is None"""
