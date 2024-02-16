# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from io import StringIO
import unittest

import sdv
import sdv.errors as errors

STIX_1_1_1_XML = \
"""
<stix:STIX_Package
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:stix="http://stix.mitre.org/stix-1"
    xmlns:indicator="http://stix.mitre.org/Indicator-2"
    xmlns:cybox="http://cybox.mitre.org/cybox-2"
    xmlns:DomainNameObj="http://cybox.mitre.org/objects#DomainNameObject-1"
    xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
    xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1"
    xmlns:example="http://example.com/"
    id="example:STIXPackage-f61cd874-494d-4194-a3e6-6b487dbb6d6e"
    timestamp="2014-05-08T09:00:00.000000Z"
    version="1.1.1"
    >
    <stix:STIX_Header>
        <stix:Title>Example watchlist that contains domain information.</stix:Title>
        <stix:Package_Intent xsi:type="stixVocabs:PackageIntentVocab-1.0">Indicators - Watchlist</stix:Package_Intent>
    </stix:STIX_Header>
    <stix:Indicators>
        <stix:Indicator xsi:type="indicator:IndicatorType" id="example:Indicator-2e20c5b2-56fa-46cd-9662-8f199c69d2c9" timestamp="2014-05-08T09:00:00.000000Z">
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Domain Watchlist</indicator:Type>
            <indicator:Description>Sample domain Indicator for this watchlist</indicator:Description>
            <indicator:Observable id="example:Observable-87c9a5bb-d005-4b3e-8081-99f720fad62b">
                <cybox:Object id="example:Object-12c760ba-cd2c-4f5d-a37d-18212eac7928">
                    <cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType" type="FQDN">
                        <DomainNameObj:Value condition="Equals" apply_condition="ANY">malicious1.example.com##comma##malicious2.example.com##comma##malicious3.example.com</DomainNameObj:Value>
                    </cybox:Properties>
                </cybox:Object>
            </indicator:Observable>
        </stix:Indicator>
    </stix:Indicators>
</stix:STIX_Package>
"""

STIX_INVALID = \
"""
<stix:STIX_Package
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:stix="http://stix.mitre.org/stix-1"
    version="1.1.1"
    badAttr="True"
    >
    <stix:STIX_Header>
        <stix:Title>Unknown version of STIX</stix:Title>
        <stix:INVALID>this is an invalid field</stix:INVALID>
    </stix:STIX_Header>
</stix:STIX_Package>
"""


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

class STIXSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        StringIO(STIX_1_1_1_XML)

    def test_invalid(self):
        xml = StringIO(STIX_INVALID)
        results = sdv.validate_xml(xml)

        # Assert that the document is identified as being invalid
        self.assertFalse(results.is_valid)

        # Assert that the badAttr attribute and stix:INVALID element are
        # errors are recorded.
        self.assertEqual(len(results.errors), 2)

    def test_valid(self):
        xml = StringIO(STIX_1_1_1_XML)
        results = sdv.validate_xml(xml)
        self.assertTrue(results.is_valid)

    def test_invalid_version(self):
        xml = StringIO(STIX_1_1_1_XML)
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

    def test_defined_version(self):
        xml = StringIO(STIX_NO_VERSION_XML)
        results = sdv.validate_xml(xml, version="1.1.1")
        self.assertTrue(results.is_valid)

    def test_invalid_doc(self):
        func = sdv.validate_xml
        self.assertRaises(errors.ValidationError, func, "INVALID XML DOC")


if __name__ == '__main__':
    unittest.main()
