# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from io import StringIO
import unittest
import datetime

from lxml import etree
import dateutil.parser
import dateutil.tz

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
        self.assertEqual(2, len(list(pairs)))

    def test_get_schemaloc_pairs_raises(self):
        sio = StringIO(XML)
        root = utils.get_etree_root(sio)
        self.assertRaises(
            KeyError,
            utils.get_schemaloc_pairs,
            root
        )

    def test_has_tzinfo(self):
        # No timezone
        now = datetime.datetime.now()
        tz_set = utils.has_tzinfo(now)
        self.assertEqual(False, tz_set)

        hastz = (
            datetime.datetime.now(tz=dateutil.tz.tzutc()),  # UTC
            dateutil.parser.parse('2015-04-14T16:10:50.658617Z'),  # Zulu
        )

        for ts in hastz:
            tz_set = utils.has_tzinfo(ts)
            self.assertEqual(True, tz_set)

    def test_has_content(self):
        a = etree.Element('a')
        b = etree.Element('b')
        c = etree.Element('c')
        c.text = 'Test'

        b.append(c)
        a.append(b)

        self.assertTrue(utils.has_content(c))
        self.assertTrue(utils.has_content(b))
        self.assertTrue(utils.has_content(a))

        no_content = etree.Element('nocontent')
        self.assertEqual(False, utils.has_content(no_content))

        only_comment = etree.XML(
            "<node>"
            "   <!-- a Comment -->"
            "</node>"
        )

        self.assertEqual(False, utils.has_content(only_comment))

    def test_is_leaf(self):
        a = etree.Element('a')
        b = etree.Element('b')
        a.append(b)

        self.assertTrue(utils.is_leaf(b))
        self.assertEqual(False, utils.is_leaf(a))

    def test_is_qname(self):
        valid = [
            "foo:bar",
            "foobar",  # No namespace prefix
            "_foo:bar",
            "foo:bar1",
            "foo:bar_-123",
            "foo-bar:foobar",
            "foo:bar.foo"
        ]

        invalid = [
            "0foo:bar",
            "-foo:bar",
            ":foobar"
        ]

        for s in valid:
            self.assertTrue(utils.is_qname(s))

        for s in invalid:
            self.assertEqual(False, utils.is_qname(s), msg=s)
