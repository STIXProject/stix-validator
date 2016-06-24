# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import os

# internal
from sdv import errors
from sdv.resources import XSD_ROOT

# relative
from . import common
from .. import xml_schema, base


class _XmlSchemaValidator(xml_schema.XmlSchemaValidator):
    """Needed to resolve namespace collisions between CybOX 2.1 and
    STIX v1.1.1.

    CybOX imports CPE 2.3. The STIX CVRF extension imports CPE 2.2a. Both
    are defined within the 'http://cpe.mitre.org/language/2.0' namespace,
    which results in a namespace collision.

    To resolve this, we force the 'http://cpe.mitre.org/language/2.0' namespace
    to map to the CPE 2.3 schemas.

    """
    OVERRIDE_SCHEMALOC = {
        'http://cpe.mitre.org/language/2.0': os.path.join(
            XSD_ROOT, 'stix_1.1.1', 'cybox', 'external', 'cpe_2.3', 'cpe-language_2.3.xsd'
        )
    }


class STIXSchemaValidator(base.BaseSchemaValidator):
    _SCHEMAS = {
        'stix-1.2.1': os.path.join(XSD_ROOT, 'stix_1.2.1'),
        '1.2': os.path.join(XSD_ROOT, 'stix_1.2'),
        '1.1.1': os.path.join(XSD_ROOT, 'stix_1.1.1'),
        '1.1': os.path.join(XSD_ROOT, 'stix_1.1'),
        '1.0.1': os.path.join(XSD_ROOT, 'stix_1.0.1'),
        '1.0': os.path.join(XSD_ROOT, 'stix_1.0')
    }

    def __init__(self, schema_dir=None):
        super(STIXSchemaValidator, self).__init__(schema_dir=schema_dir)

    def _get_document_version(self, doc):
        return common.get_version(doc)

    def _raise_invalid_version(self, version):
        error = (
            "Invalid STIX version number provided or found in input "
            "document: '{0}'"
        ).format(version)

        raise errors.InvalidSTIXVersionError(
            message=error,
            expected=common.STIX_VERSIONS,
            found=version
        )

    def _get_validator_impl(self, schema_dir=None):
        return _XmlSchemaValidator(schema_dir=schema_dir)

    @common.check_stix
    def validate(self, doc, version=None, schemaloc=False):
        """Performs XML Schema validation against a STIX document.

        When validating against the set of bundled schemas, a STIX version
        number must be declared for the input `doc`. If a user does not pass in
        a `version` parameter, an attempt will be made to collect the version
        from the input `doc`.

        Note:
            If `schemaloc` is ``True`` or this class was initialized with a
            ``schema_dir``, no version checking or verification will occur.

        Args:
            doc: The STIX document. This can be a filename, file-like object,
                ``etree._Element``, or ``etree._ElementTree`` instance.
            version: The version of the STIX document. If ``None`` an attempt
                will be made to extract the version from `doc`.
            schemaloc: If ``True``, the ``xsi:schemaLocation`` attribute on
                `doc` will be used to drive the validation.

        Returns:
            An instance of
            :class:`.XmlValidationResults`.

        Raises:
            .UnknownSTIXVersionError: If `version` is ``None`` and
                `doc` does not contain STIX version information.
            .InvalidSTIXVersionError: If `version` is an invalid
                STIX version or `doc` contains an invalid STIX version number.
            .ValidationError: If the class was not initialized with a
                schema directory and `schemaloc` is ``False``.
            .XMLSchemaImportError: If an error occurs while processing the
                schemas required for validation.
            .XMLSchemaIncludeError: If an error occurs while processing
                ``xs:include`` directives.
            .ValidationError: If there are any issues parsing `doc`.

        """
        return self._validate(doc=doc, version=version, schemaloc=schemaloc)


__all__ = [
    'STIXSchemaValidator'
]
