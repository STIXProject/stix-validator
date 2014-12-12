# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import os
from version import __version__

_PKG_DIR = os.path.dirname(__file__)
XSD_ROOT = os.path.abspath(os.path.join(_PKG_DIR, 'xsd'))

# A cache of STIX XML validators that speeds up consecutive calls to
# validate_xml() against non-bundled schema directories.
__xml_validators = {}

# A cache of STIX Profile validators to speed up consecutive calls to
# validate_profile()
__profile_validators = {}


def validate_xml(doc, version=None, schemas=None, schemaloc=False):
    """Performs `XML Schema`_ validation against a STIX document.

    .. _XML Schema: http://stix.mitre.org/language/

    Args:
        doc: A STIX document to validate. This can be a filename, file-like
            object, ``etree._Element`` or ``etree._ElementTree`` object.
        version: The version of the STIX document being validated. If ``None``
            an attempt will be made to extract the version from `doc`.
        schemas: A string path to a directory of STIX schemas. If ``None``,
            the validation code will leverage its bundled STIX schemas.
        schemaloc: Use ``xsi:schemaLocation`` attribute on `doc` to perform
            validation.

    Note:
        The first time running this for a given `schemas` (or no `schemas`)
        will take longer than following validation runs due to schema
        compilation time.

    Returns:
        An instance of
        :class:`.XmlValidationResults`.

    Raises:
        IOError: If `doc` is not a valid XML document or there is an issue
            processing `schemas`.
        .UnknownSTIXVersionError: If `version` is ``None`` and
            `doc` does not contain a ``@version`` attribute value.
        .InvalidSTIXVersionError: If `version` or the ``version``
            attribute in `doc` contains an invalid STIX version number.
        .ValidationError: If the class was not initialized with a schema
                directory and `schemaloc` is ``False``.
        .XMLSchemaImportError: If an error occurs while processing
            the schemas required for validation.
        .XMLSchemaIncludeError: If an error occurs while
            processing ``xs:include`` directives.

    """
    from sdv.validators import STIXSchemaValidator

    try:
        validator = __xml_validators[schemas]
    except KeyError:
        validator = STIXSchemaValidator(schema_dir=schemas)
        __xml_validators[schemas] = validator

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
        .InvalidSTIXVersionError: If `version` or the ``@version`` attribute
            in `doc` contains an invalid STIX version number.

    """
    from sdv.validators import STIXBestPracticeValidator

    validator = STIXBestPracticeValidator()
    return validator.validate(doc, version=version)


def validate_profile(doc, profile):
    """Performs `STIX Profile`_ validation against a STIX document.

    .. _STIX Profile: http://stixproject.github.io/documentation/profiles/

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

    try:
        validator = __profile_validators[profile]
    except KeyError:
        validator = STIXProfileValidator(profile)
        __profile_validators[profile] = validator

    return validator.validate(doc)
