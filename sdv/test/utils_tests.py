# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
from StringIO import StringIO

from lxml import etree

import sdv.utils as utils
import sdv.errors as errors

BROKEN_XML = "<foo>BROKEN MISMATCHED TAGS</bar>"
TARGET_NS = "http://example.com/"
XML = "<xml targetNamespace='%s'>test</xml>" % TARGET_NS
XML_ROOT_LOCALNAME = "xml"

XML_SCHEMALOC = \
"""
<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="
http://cybox.mitre.org/common-2 http://cybox.mitre.org/XMLSchema/common/2.1/cybox_common.xsd
http://cybox.mitre.org/cybox-2 http://cybox.mitre.org/XMLSchema/core/2.1/cybox_core.xsd"/>
"""

class UtilsTests(unittest.TestCase):
    def test_get_parser(self):
        parser = utils.get_xml_parser()
        self.assertTrue(isinstance(parser, etree.ETCompatXMLParser))

    def test_get_etree_root_stringio(self):
        sio = StringIO(XML)
        root = utils.get_etree_root(sio)
        lname = etree.QName(root).localname
        self.assertEqual(lname, XML_ROOT_LOCALNAME)

    def test_get_etree_root_element(self):
        sio = StringIO(XML)
        tree = etree.parse(sio)
        newroot = tree.getroot()
        root = utils.get_etree_root(newroot)
        lname = etree.QName(root).localname
        self.assertEqual(lname, XML_ROOT_LOCALNAME)

    def test_get_etree_root_elementree(self):
        tree = etree.fromstring(XML)
        root = utils.get_etree_root(tree)
        lname = etree.QName(root).localname
        self.assertEqual(lname, XML_ROOT_LOCALNAME)

    def test_get_etree_root_raises(self):
        sio = StringIO(BROKEN_XML)
        self.assertRaises(
            errors.ValidationError,
            utils.get_etree_root,
            sio
        )

    def test_target_ns(self):
        sio = StringIO(XML)
        target_ns = utils.get_target_ns(sio)
        self.assertEqual(target_ns, TARGET_NS)

    def test_get_schemaloc_pairs(self):
        sio = StringIO(XML_SCHEMALOC)
        root = utils.get_etree_root(sio)
        pairs = utils.get_schemaloc_pairs(root)
        self.assertEqual(2, len(pairs))

    def test_get_schemaloc_pairs_raises(self):
        sio = StringIO(XML)
        root = utils.get_etree_root(sio)
        self.assertRaises(
            KeyError,
            utils.get_schemaloc_pairs,
            root
        )

