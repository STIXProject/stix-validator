# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from io import StringIO
import unittest

import sdv
import sdv.errors as errors
from sdv.validators.stix.profile import InstanceMapping

STIX_NO_VERSION_XML = \
"""
<stix:STIX_Package
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:stix="http://stix.mitre.org/stix-1"
    >
    <stix:STIX_Header>
        <stix:Title>Unknown version of STIX</stix:Title>
    </stix:STIX_Header>
</stix:STIX_Package>
"""

class STIXProfileTests(unittest.TestCase):
    def test_invalid_profile(self):
        xml = StringIO(STIX_NO_VERSION_XML)
        func = sdv.validate_profile
        self.assertRaises(errors.ProfileParseError, func, xml, "INVALID Profile DOC")


class InstanceMappingTests(unittest.TestCase):
    _NSMAP = {
        'http://stix.mitre.org/stix-1': 'stix'
    }
    _NAMESPACE = "http://stix.mitre.org/stix-1"
    _SELECTORS = "stix:STIX_Package, //stix:Package"
    _LABEL = "STIXType"

    def test_missing_label(self):
        mapping = InstanceMapping(self._NSMAP)
        mapping.selectors = "stix:STIX_Package, //stix:Package"
        mapping.namespace = self._NAMESPACE
        self.assertRaises(errors.ProfileParseError, mapping.validate)

    def test_missing_namespace(self):
        mapping = InstanceMapping(self._NSMAP)
        mapping.selectors = "stix:STIX_Package, //stix:Package"
        mapping.label = "STIXType"
        self.assertRaises(errors.ProfileParseError, mapping.validate)

    def test_invalid_namespace(self):
        mapping = InstanceMapping(self._NSMAP)
        mapping.selectors = "stix:STIX_Package, //stix:Package"
        mapping.label = "STIXType"

        def set_namespace():
            mapping.namespace = "this will fail"

        self.assertRaises(errors.ProfileParseError, set_namespace)

if __name__ == '__main__':
    unittest.main()
