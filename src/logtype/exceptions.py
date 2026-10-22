class LogTypeError(Exception):
    """Base class for errors while detecting the type of a logfile."""


class LogFileEmpty(LogTypeError):
    """Raised when no line of the logfile could be read as the log type."""


class SkipFile(Exception):
    """Base class for signals that a file should be skipped."""


class IgnoredFile(SkipFile):
    """Raised when the path matches a pattern in the ignore list."""


class FoundInTypes(SkipFile):
    """Raised when the path is listed in the types file."""
