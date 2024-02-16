# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from io import StringIO
import unittest

import sdv
import sdv.errors as errors

CYBOX_2_1_XML = \
"""
<cybox:Observables xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:cybox="http://cybox.mitre.org/cybox-2"
    xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
    xmlns:URIObject="http://cybox.mitre.org/objects#URIObject-2"
    xmlns:example="http://example.com/"
    cybox_major_version="2"
    cybox_minor_version="1"
    cybox_update_version="0">
    <cybox:Observable id="example:Observable-0b9af310-0d5a-4c44-bdd7-aea3d99f13b6">
        <cybox:Object id="example:Object-15be6630-b2df-4bf9-8750-3f45ca9e19cf">
            <cybox:Properties xsi:type="URIObject:URIObjectType" type="Domain Name">
                <URIObject:Value>example.com</URIObject:Value>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
</cybox:Observables>
"""

CYBOX_2_1_NO_UPDATE_VER_XML = \
"""
<cybox:Observables xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:cybox="http://cybox.mitre.org/cybox-2"
    xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
    xmlns:URIObject="http://cybox.mitre.org/objects#URIObject-2"
    xmlns:example="http://example.com/"
    cybox_major_version="2"
    cybox_minor_version="1">
    <cybox:Observable id="example:Observable-0b9af310-0d5a-4c44-bdd7-aea3d99f13b6">
        <cybox:Object id="example:Object-15be6630-b2df-4bf9-8750-3f45ca9e19cf">
            <cybox:Properties xsi:type="URIObject:URIObjectType" type="Domain Name">
                <URIObject:Value>example.com</URIObject:Value>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
</cybox:Observables>
"""

CYBOX_INVALID = \
"""
<cybox:Observables xmlns:cybox="http://cybox.mitre.org/cybox-2"
    cybox_major_version="2"
    cybox_minor_version="1"
    cybox_update_version="0">
    <cybox:BAD_ELEMENT>This should raise an error</cybox:BAD_ELEMENT>
</cybox:Observables>
"""


class CyboxSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        StringIO(CYBOX_2_1_XML)

    def test_invalid(self):
        xml = StringIO(CYBOX_INVALID)
        results = sdv.validate_xml(xml)

        # Assert that the document is identified as being invalid
        self.assertFalse(results.is_valid)

        # Assert that the badAttr attribute is the only error recorded
        self.assertEqual(len(results.errors), 1)

    def test_valid(self):
        xml = StringIO(CYBOX_2_1_XML)
        results = sdv.validate_xml(xml)
        self.assertTrue(results.is_valid)

    def test_invalid_version(self):
        xml = StringIO(CYBOX_2_1_XML)
        func = sdv.validate_xml
        self.assertRaises(
            errors.InvalidCyboxVersionError, func, xml, version="INVALID"
        )

    def test_defined_version(self):
        xml = StringIO(CYBOX_2_1_XML)
        results = sdv.validate_xml(xml, version="2.1")
        self.assertTrue(results.is_valid)

    def test_invalid_doc(self):
        func = sdv.validate_xml
        self.assertRaises(errors.ValidationError, func, "INVALID XML DOC")


if __name__ == '__main__':
    unittest.main()
