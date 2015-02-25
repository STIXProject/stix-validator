# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# internal
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


__all__ = [
    'ValidationError',
    'ValidationResults'
]