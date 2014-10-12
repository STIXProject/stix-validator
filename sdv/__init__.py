import os
import json
from version import __version__

_PKG_DIR = os.path.dirname(__file__)
XSD_ROOT = os.path.abspath(os.path.join(_PKG_DIR, 'xsd'))

class ValidationError(Exception):
    pass

class _BaseValidationResults(object):
    def __init__(self):
        self.is_valid = None
        self.errors = None

    @property
    def errors(self):
        return self._errors

    @errors.setter
    def errors(self, value):
        self._errors = value


    def as_dict(self):
        d = {}
        d['result'] = self.is_valid

        if self.errors:
            d['errors'] = self.errors

        return d

    def as_json(self):
        return json.dumps(self.as_dict())