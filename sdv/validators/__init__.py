# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import json

from .base import ValidationResults

class ValidationErrorResults(ValidationResults):
    """Can be used to communicate a failed validation due to a raised Exception.

    Note:
        This is only used by the ``stix_validator.py`` script at the moment and
        not actually returned from any ``validate()`` methods.

    Args:
        error: An ``Exception`` instance raised by validation code.

    Attributes:
        is_valid: Always ``False``.
        error: The string representation of the Exception being passed in.
        exception: The exception which produced these results.

    """
    def __init__(self, error):
        self._is_valid = False
        self.error = str(error)
        self.exception = error

    def as_dict(self):
        d = super(ValidationErrorResults, self).as_dict()
        d['error'] = self.error

        return d

from .xml_schema import *
from .schematron import *
from .stix import *


__all__ = [
    'ValidationError',
    'ValidationErrorResults',
    'ValidationResults'
]
