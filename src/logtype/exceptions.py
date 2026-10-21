class LogTypeException(Exception):
    """Exceptions for checking logtypes."""


class LogFileEmpty(LogTypeException):
    """When logfile was empty while checking."""


class LogTypeError(Exception):
    """General errors."""


class Ignores(Exception):
    """Top-level exception for all results to ignore."""


class IgnoredFile(Ignores):
    """This result was found in ignored file."""


class FoundInTypes(Ignores):
    """This result was found in types."""
