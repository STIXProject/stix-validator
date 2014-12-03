# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
import unittest
from StringIO import StringIO
from lxml import etree

import sdv
import sdv.errors as errors
import sdv.validators.stix.best_practice as bp

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
        func = sdv.validate_best_practices
        self.assertRaises(
            errors.InvalidSTIXVersionError, func, xml, version="INVALID"
        )

    def test_unknown_version(self):
        func = sdv.validate_best_practices
        xml = StringIO(STIX_NO_VERSION_XML)
        self.assertRaises(
            errors.UnknownSTIXVersionError, func, xml
        )

    def test_invalid_doc(self):
        func = sdv.validate_best_practices
        self.assertRaises(errors.ValidationError, func, "INVALID XML DOC")


class BestPracticeWarningTests(unittest.TestCase):
    def test_core_keys(self):
        node = etree.Element("test")
        warning = bp.BestPracticeWarning(node)

        for key in warning.core_keys:
            self.assertTrue(key in warning, key)

    def test_other_keys(self):
        node = etree.Element("test")
        warning = bp.BestPracticeWarning(node)
        warning['foo'] = 'bar'
        self.assertTrue('foo' in warning.other_keys)




if __name__ == '__main__':
    unittest.main()
