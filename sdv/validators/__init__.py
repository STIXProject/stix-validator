# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from sdv import errors, utils
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
from .cybox import *


def get_xml_validator_class(doc):
    """Returns the XML validator class required to validate the input
    `doc`.

    Args:
        doc: An XML document. This can be a filename, file-like object,
            ``etree._Element``, or ``etree._ElementTree`` instance.

    Returns:
        An XML Schema validator class (not object instance) which provides
        validation functionality required to validate `doc`.

    """
    root = utils.get_etree_root(doc)

    if utils.is_stix(root):
        return STIXSchemaValidator

    if utils.is_cybox(root):
        return CyboxSchemaValidator

    ns = utils.get_namespace(root)
    error = (
        "Unable determine validator class for input type. Root element "
        "namespace: {0}"
    ).format(ns)

    raise errors.ValidationError(error)
