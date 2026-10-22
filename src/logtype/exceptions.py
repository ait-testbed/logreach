class LogTypeError(Exception):
    """Base class for errors while detecting the type of a logfile."""


class LogFileEmpty(LogTypeError):
    """Raised when the logfile is empty."""


class SkipFile(Exception):
    """Base class for signals that a file should be skipped."""


class IgnoredFile(SkipFile):
    """Raised when the path matches a pattern in the ignore list."""
