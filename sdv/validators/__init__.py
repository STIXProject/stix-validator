# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import json


class ValidationError(object):
    """Base class for validation error types."""
    def __init__(self):
        pass

    def as_dict(self):
        raise NotImplementedError()

    def as_json(self):
        """Returns a JSON representation of this class instance."""
        return json.dumps(self.as_dict())


class ValidationResults(object):
    """Base class for all validation result types."""

    def __init__(self, is_valid=False):
        self.is_valid = is_valid

    @property
    def is_valid(self):
        """Returns ``True`` if the validation attempt was successful and
        ``False`` otherwise.

        """
        return self._is_valid

    @is_valid.setter
    def is_valid(self, value):
        self._is_valid = bool(value)

    def as_dict(self):
        """Returns a dictionary representation of this class.

        Keys:
            ``'result'``: The validation result. Values will be ``True`` or
            ``False``.

        """
        return {'result': self.is_valid}

    def as_json(self):
        """Returns a JSON representation of this class instance."""
        return json.dumps(self.as_dict())


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

from .schematron import *
from .xml_schema import *
from .stix import *
