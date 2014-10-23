# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import os
import json
from version import __version__
import errors

_PKG_DIR = os.path.dirname(__file__)
XSD_ROOT = os.path.abspath(os.path.join(_PKG_DIR, 'xsd'))

class ValidationResults(object):
    """Base class for all validation result types."""

    def __init__(self, is_valid=False):
        self.is_valid = is_valid

    @property
    def is_valid(self):
        """``True`` if the validation attempt was successful and ``False
        otherwise.

        """
        return self._is_valid

    @is_valid.setter
    def is_valid(self, value):
        self._is_valid = bool(value)

    def as_dict(self):
        """Returns a dictionary representation of the ``ValidationResults``
        instance.

        Keys:
            'result': The validation result. Values will be ``True`` or
                ``False``.

        """
        return {'result': self.is_valid}

    def as_json(self):
        """Returns a JSON representation of the ``ValidationResults`` class
        instance.

        """
        return json.dumps(self.as_dict())


def validate_xml(doc, version=None, schemas=None, schemaloc=False):
    """Performs XML Schema validation against a STIX document.

    Args:
        doc: A STIX document to validate. This can be a filename, file-like
            object, etree._Element or etree._ElementTree object.
        version: The version of the STIX document being validated. If ``None``
            an attempt will be made to extract the version from `doc`.
        schemas: A string path to a directory of STIX schemas. If ``None``,
            the validation code will leverage its bundled schemas.
        schemaloc: Use ``xsi:schemaLocation`` attribute on `doc` to perform
            validation.

    Returns:
        An instance of sdv.validators.XmlSchemaValidationResults.

    Raises:
        IOError: If `doc` is not a valid XML document or there is an issue
            processing `schemas`.
        errors.UnknownVersionError: If `version` is ``None`` and
            `doc` does not contain verison information.
        errors..validators.stix.InvalidVersionError: If `version` or the ``version`` attribute in `doc`
            contains an invalid STIX version number.
        errors.ValidationError: If the class was not initialized with a schema
                directory and `schemaloc` is ``False``.
        errors.ImportProcessError: If an error occurs while processing the schemas
                required for validation.
        errors.IncludeProcessError: If an error occurs while processing
                ``xs:include`` directives.

    """
    from sdv.validators import STIXSchemaValidator
    validator = STIXSchemaValidator(schema_dir=schemas)
    results = validator.validate(doc, version=version, schemaloc=schemaloc)
    return results


def validate_best_practices(doc, version=None):
    """Performs 'Best Practice' validation against a STIX document.

    Note:
        This should be used together with :meth:`validate_xml` since this only
        checks best practices and not schema-conformance.

    Args:
        doc: A STIX document to validate. This can be a filename, file-like
            object, etree._Element or etree._ElementTree object.
        version: The version of the STIX document being validated. If ``None``
            an attempt will be made to extract the version from `doc`.

    Returns:
        An instance of sdv.validators.BestPracticeValidationResults.

    Raises:
        IOError: If `doc` is not a valid XML document.
        errors.UnknownVersionError: If `version` is ``None`` and
            `doc` does not contain verison information.
        errors.validators.stix.InvalidVersionError: If `version` or the ``version`` attribute in `doc`
            contains an invalid STIX version number.

    """
    from sdv.validators import STIXBestPracticeValidator
    validator = STIXBestPracticeValidator()
    results = validator.validate(doc, version=version)
    return results


def validate_profile(doc, profile):
    """Performs STIX Profile validation against a STIX document.

    Note:
        This should be used together with :meth:`validate_xml` since this only
        checks profile-conformance and not schema-conformance.

    Args:
        doc: A STIX document to validate. This can be a filename, file-like
            object, etree._Element or etree._ElementTree object.
        profile: A filename to a STIX Profile document.

    Returns:
    `   An instance of sdv.validators.ProfileValidationResults.

    Raises:
        IOError: If `doc` is not a valid XML document.
        errors.ProfileParseError: If an error occurred while attempting to
            parse the `profile`.

    """
    from sdv.validators import STIXProfileValidator
    validator = STIXProfileValidator(profile)
    results = validator.validate(doc)
    return results