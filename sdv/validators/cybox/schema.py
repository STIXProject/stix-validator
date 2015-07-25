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


class CyboxSchemaValidator(base.BaseSchemaValidator):
    _SCHEMAS = {
        '2.1': os.path.join(XSD_ROOT, 'stix_1.1.1', 'cybox'),
        '2.0.1': os.path.join(XSD_ROOT, 'stix_1.0.1', 'cybox'),
        '2.0': os.path.join(XSD_ROOT, 'stix_1.0', 'cybox')
    }

    def __init__(self, schema_dir=None):
        super(CyboxSchemaValidator, self).__init__()

    def _get_document_version(self, doc):
        return common.get_version(doc)

    def _raise_invalid_version(self, version):
        error = (
            "Invalid CybOX version number provided or found in input "
            "document: '{0}'"
        ).format(version)

        raise errors.InvalidCyboxVersionError(
            message=error,
            found=version,
            expected=common.CYBOX_VERSIONS
        )

    def _get_validator_impl(self, schema_dir=None):
        return xml_schema.XmlSchemaValidator(schema_dir=schema_dir)

    @common.check_cybox
    def validate(self, doc, version=None, schemaloc=False):
        """Performs XML Schema validation against a CybOX document.

        When validating against the set of bundled schemas, a CybOX version
        number must be declared for the input `doc`. If a user does not pass in
        a `version` parameter, an attempt will be made to collect the version
        from the input `doc`.

        Note:
            If `schemaloc` is ``True`` or this class was initialized with a
            ``schema_dir``, no version checking or verification will occur.

        Args:
            doc: The CybOX document. This can be a filename, file-like object,
                ``etree._Element``, or ``etree._ElementTree`` instance.
            version: The version of the CybOX document. If ``None`` an attempt
                will be made to extract the version from `doc`.
            schemaloc: If ``True``, the ``xsi:schemaLocation`` attribute on
                `doc` will be used to drive the validation.

        Returns:
            An instance of
            :class:`.XmlValidationResults`.

        Raises:
            .UnknownCyboxVersionError: If `version` is ``None`` and
                `doc` does not contain CybOX version information.
            .InvalidCyboxVersionError: If `version` is an invalid
                CybOX version or `doc` contains an invalid CybOX version
                number.
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
    'CyboxSchemaValidator'
]
