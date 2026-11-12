"""Read logfiles of detected types, filtered by time; see Logreach."""

import logging

from logreach.api import FileEvent, FileStatus, Logreach, Problems
from logreach.exceptions import DateTimeNotFound, LogreachError, LogTypeError
from logreach.schemas.logfileconfig import LogConfig, LogType
from logreach.schemas.logline import Logline

# a library only logs; the application decides where to
logging.getLogger('logreach').addHandler(logging.NullHandler())

__all__ = ['DateTimeNotFound', 'FileEvent', 'FileStatus', 'LogConfig', 'LogType', 'Logline', 'Logreach',
           'LogreachError', 'LogTypeError', 'Problems']
