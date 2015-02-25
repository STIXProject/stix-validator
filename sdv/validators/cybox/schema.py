# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import os

# internal
import sdv
import sdv.utils as utils

# relative
from . import common as cybox
from .. import xml_schema as xml



class CyboxSchemaValidator(object):
    SCHEMAS = {
        '2.1': os.path.join(sdv.XSD_ROOT, 'stix_1.1.1', 'cybox'),
        '2.0.1': os.path.join(sdv.XSD_ROOT, 'stix_1.0.1', 'cybox'),
        '2.0': os.path.join(sdv.XSD_ROOT, 'stix_1.0', 'cybox')
    }

    _KEY_SCHEMALOC = 'schemaloc'
    _KEY_USER_DEFINED = 'user'

    def __init__(self, schema_dir=None):
        self._xml_validators = self._get_validators(schema_dir)
        self._is_user_defined = bool(schema_dir)

    def _get_validators(self, schema_dir=None):
        validators = {self._KEY_SCHEMALOC: xml.XmlSchemaValidator()}

        if schema_dir:
            validators = {
                self._KEY_USER_DEFINED: xml.XmlSchemaValidator(schema_dir)
            }
        else:
            for version, location in self.SCHEMAS.iteritems():
                validator = xml.XmlSchemaValidator(location)
                validators[version] = validator

        return validators

    @cybox.check_cybox
    def validate(self, doc, version=None, schemaloc=False):
        """Performs XML Schema validation against a CybOX document.

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
                CybOX version or `doc` contains an invalid CybOX version number.
            .ValidationError: If the class was not initialized with a
                schema directory and `schemaloc` is ``False``.
            .XMLSchemaImportError: If an error occurs while processing the
                schemas required for validation.
            .XMLSchemaIncludeError: If an error occurs while processing
                ``xs:include`` directives.
            .ValidationError: If there are any issues parsing `doc`.

        """
        root = utils.get_etree_root(doc)

        if schemaloc:
            validator = self._xml_validators[self._KEY_SCHEMALOC]
        elif self._is_user_defined:
            validator = self._xml_validators[self._KEY_USER_DEFINED]
        else:
            version = version or cybox.get_version(doc)
            validator = self._xml_validators[version]

        results = validator.validate(root, schemaloc)
        return results


__all__ = [
    'CyboxSchemaValidator'
]
