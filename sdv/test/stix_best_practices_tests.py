# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
import unittest
from StringIO import StringIO

import sdv
import sdv.errors as errors

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

class STIXBestPracticesTests(unittest.TestCase):
    def test_invalid_version(self):
        xml = StringIO(STIX_NO_VERSION_XML)
        func = sdv.validate_xml
        self.assertRaises(
            errors.InvalidSTIXVersionError, func, xml, version="INVALID"
        )

    def test_unknown_version(self):
        func = sdv.validate_xml
        xml = StringIO(STIX_NO_VERSION_XML)
        self.assertRaises(
            errors.UnknownSTIXVersionError, func, xml
        )

    def test_invalid_doc(self):
        func = sdv.validate_xml
        self.assertRaises(errors.ValidationError, func, "INVALID XML DOC")

if __name__ == '__main__':
    unittest.main()
