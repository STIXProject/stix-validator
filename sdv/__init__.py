# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import os
from version import __version__
import errors

_PKG_DIR = os.path.dirname(__file__)
XSD_ROOT = os.path.abspath(os.path.join(_PKG_DIR, 'xsd'))

from sdv.validators import STIXSchemaValidator
DEFAULT_STIX_VALIDATOR = STIXSchemaValidator()  # Makes validate_xml() faster

def validate_xml(doc, version=None, schemas=None, schemaloc=False):
    """Performs XML Schema validation against a STIX document.

    Args:
        doc: A STIX document to validate. This can be a filename, file-like
            object, ``etree._Element`` or ``etree._ElementTree`` object.
        version: The version of the STIX document being validated. If ``None``
            an attempt will be made to extract the version from `doc`.
        schemas: A string path to a directory of STIX schemas. If ``None``,
            the validation code will leverage its bundled schemas.
        schemaloc: Use ``xsi:schemaLocation`` attribute on `doc` to perform
            validation.

    Returns:
        An instance of
        :class:`.XmlValidationResults`.

    Raises:
        IOError: If `doc` is not a valid XML document or there is an issue
            processing `schemas`.
        .UnknownSTIXVersionError: If `version` is ``None`` and
            `doc` does not contain versin information.
        .InvalidSTIXVersionError: If `version` or the ``version``
            attribute in `doc` contains an invalid STIX version number.
        .ValidationError: If the class was not initialized with a schema
                directory and `schemaloc` is ``False``.
        .XMLSchemaImportError: If an error occurs while processing
            the schemas required for validation.
        .XMLSchemaIncludeError: If an error occurs while
            processing ``xs:include`` directives.

    """
    if schemas:
        validator = STIXSchemaValidator(schema_dir=schemas)
    else:
        validator = DEFAULT_STIX_VALIDATOR

    return validator.validate(doc, version=version, schemaloc=schemaloc)


def validate_best_practices(doc, version=None):
    """Performs `Best Practices`_ validation against a STIX document.

    .. _Best Practices: http://stixproject.github.io/documentation/suggested-practices/

    Note:
        This should be used together with :meth:`validate_xml` since this only
        checks best practices and not schema-conformance.

    Args:
        doc: A STIX document to validate. This can be a filename, file-like
            object, ``etree._Element`` or ``etree._ElementTree`` object.
        version: The version of the STIX document being validated. If ``None``
            an attempt will be made to extract the version from `doc`.

    Returns:
        An instance of
        :class:`.BestPracticeValidationResults`.

    Raises:
        IOError: If `doc` is not a valid XML document.
        .UnknownSTIXVersionError: If `version` is ``None`` and
            `doc` does not contain version information.
        .InvalidSTIXVersionError: If `version` or the ``version`` attribute
            in `doc` contains an invalid STIX version number.

    """
    from sdv.validators import STIXBestPracticeValidator

    validator = STIXBestPracticeValidator()
    return validator.validate(doc, version=version)


def validate_profile(doc, profile):
    """Performs STIX Profile validation against a STIX document.

    Note:
        This should be used together with :meth:`validate_xml` since this only
        checks profile-conformance and not schema-conformance.

    Args:
        doc: A STIX document to validate. This can be a filename, file-like
            object, ``etree._Element`` or ``etree._ElementTree`` object.
        profile: A filename to a STIX Profile document.

    Returns:
        An instance of
        :class:`.ProfileValidationResults`.

    Raises:
        IOError: If `doc` is not a valid XML document.
        .ProfileParseError: If an error occurred while attempting to
            parse the `profile`.

    """
    from sdv.validators import STIXProfileValidator

    validator = STIXProfileValidator(profile)
    return validator.validate(doc)

