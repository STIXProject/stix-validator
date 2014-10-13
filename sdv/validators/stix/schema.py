# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import os

from sdv import (XSD_ROOT, ValidationError)
import sdv.utils as utils
from sdv.validators import XmlSchemaValidator
import common as stix

class STIXSchemaValidator(object):
    SCHEMAS = {
        '1.1.1': os.path.join(XSD_ROOT, 'stix_1.1.1'),
        '1.1': os.path.join(XSD_ROOT, 'stix_1.1'),
        '1.0.1': os.path.join(XSD_ROOT, 'stix_1.0.1'),
        '1.0': os.path.join(XSD_ROOT, 'stix_1.0')
    }

    _KEY_SCHEMALOC = 'schemaloc'
    _KEY_USER_DEFINED = 'user'

    def __init__(self, schema_dir=None):
        self._xml_validators = self._get_validators(schema_dir)
        self._is_user_defined = bool(schema_dir)


    def _get_validators(self, schema_dir=None):
        validators = {self._KEY_SCHEMALOC: XmlSchemaValidator()}

        if schema_dir:
            validators = {
                self._KEY_USER_DEFINED: XmlSchemaValidator(schema_dir)
            }
        else:
            for version, location in self.SCHEMAS.iteritems():
                validator = XmlSchemaValidator(location)
                validators[version] = validator

        return validators


    def validate(self, doc, version=None, schemaloc=False):
        root = utils.get_etree_root(doc)
        version = version or stix.get_version(root)

        if not any((version, schemaloc, self._is_user_defined)):
            raise ValidationError(
                "Unable to validate instance document. STIX version not "
                "found in instance document and not supplied to validate() "
                "method"
            )

        if schemaloc:
            validator = self._xml_validators[self._KEY_SCHEMALOC]
        elif self._is_user_defined:
            validator = self._xml_validators[self._KEY_USER_DEFINED]
        else:
            try:
                validator = self._xml_validators[version]
            except KeyError:
                raise stix.InvalidVersionError(
                    message="No schemas for STIX version %s" % version,
                    expected=self.SCHEMAS.keys(),
                    found=version
                )

        results = validator.validate(root, schemaloc)
        return results