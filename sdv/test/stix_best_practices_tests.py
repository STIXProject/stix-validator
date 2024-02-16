# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from io import StringIO
import json
import unittest

from lxml import etree

import sdv
import sdv.errors as errors
import sdv.utils as utils
import sdv.validators.stix.best_practice as bp
from sdv.validators.stix import common

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

BP_INVALID_XML = \
"""<?xml version="1.0" encoding="UTF-8"?>
<stix:STIX_Package
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:stix="http://stix.mitre.org/stix-1"
	xmlns:stixCommon="http://stix.mitre.org/common-1"
	xmlns:indicator="http://stix.mitre.org/Indicator-2"
	xmlns:ttp="http://stix.mitre.org/TTP-1"
	xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1"
	xmlns:cybox="http://cybox.mitre.org/cybox-2"
	xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
	xmlns:DomainNameObj="http://cybox.mitre.org/objects#DomainNameObject-1"
	xmlns:marking="http://data-marking.mitre.org/Marking-1"
	xmlns:example="http://example.com/"
	xsi:schemaLocation="
	http://stix.mitre.org/stix-1 http://stix.mitre.org/XMLSchema/core/1.1.1/stix_core.xsd
	http://stix.mitre.org/common-1 http://stix.mitre.org/XMLSchema/common/1.1.1/stix_common.xsd
	http://stix.mitre.org/Indicator-2 http://stix.mitre.org/XMLSchema/indicator/2.1.1/indicator.xsd
	http://stix.mitre.org/TTP-1 http://stix.mitre.org/XMLSchema/ttp/1.1.1/ttp.xsd
	http://stix.mitre.org/default_vocabularies-1 http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.1/stix_default_vocabularies.xsd
	http://cybox.mitre.org/cybox-2 http://cybox.mitre.org/XMLSchema/core/2.1/cybox_core.xsd
	http://cybox.mitre.org/common-2 http://cybox.mitre.org/XMLSchema/common/2.1/cybox_common.xsd
	http://cybox.mitre.org/objects#DomainNameObject-1 http://cybox.mitre.org/XMLSchema/objects/Domain_Name/1.0/Domain_Name_Object.xsd
	http://data-marking.mitre.org/Marking-1  http://stix.mitre.org/XMLSchema/data_marking/1.1.1/data_marking.xsd"
	id="example:Indicator-ba1d406e-937c-414f-9231-6e1dbe64fe8b" version="1.1.1" timestamp="2014-05-08T09:00:00.000000Z">
	<stix:STIX_Header>
		<stix:Title>STIX Validator Example</stix:Title>
		<stix:Package_Intent xsi:type="stixVocabs:PackageIntentVocab-1.0">Indicators</stix:Package_Intent>
		<stix:Description>
			This example document is invalid against the STIX Suggested Practices.

			STIX Suggested Practices state that Indicators should have a Title, Valid_Time_Position, Indicated_TTP and Confidence. The
			only Indicator in this document is missing all of these properties except the Title.
		</stix:Description>
		<stix:Handling>
			<marking:Marking>
				<marking:Controlled_Structure>This is not XPath</marking:Controlled_Structure>
			</marking:Marking>
		</stix:Handling>
	</stix:STIX_Header>
	<stix:Observables cybox_major_version="2" cybox_minor_version="1">
		<cybox:Observable id="example:Observable-12c760ba-cd2c-4f5d-a37d-18212eac7929">
			<cybox:Object>
				<cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType" type="FQDN">
					<cyboxCommon:Custom_Properties>
						<cyboxCommon:Property name="test">No condition attribute!</cyboxCommon:Property>
					</cyboxCommon:Custom_Properties>
					<DomainNameObj:Value apply_condition="ANY">malicious1.example.com##comma##malicious2.example.com##comma##malicious3.example.com</DomainNameObj:Value>
				</cybox:Properties>
			</cybox:Object>
		</cybox:Observable>
	</stix:Observables>
	<stix:Indicators>
		<stix:Indicator xsi:type="indicator:IndicatorType" id="example:Indicator-2e20c5b2-56fa-46cd-9662-8f199c69d2c9" timestamp="2014-02-20T09:00:00.000000Z" version="2.1">
			<indicator:Title>Sample Domain Watchlist Indicator</indicator:Title>
			<indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.0">Domain Watchlist</indicator:Type>
			<indicator:Description>Sample domain Indicator for this watchlist</indicator:Description>
			<indicator:Observable id="example:Observable-87c9a5bb-d005-4b3e-8081-99f720fad62b">
				<cybox:Object id="example:Object-12c760ba-cd2c-4f5d-a37d-18212eac7928">
					<cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType" type="FQDN">
						<cyboxCommon:Custom_Properties>
							<cyboxCommon:Property name="test">No condition attribute!</cyboxCommon:Property>
						</cyboxCommon:Custom_Properties>
						<DomainNameObj:Value apply_condition="ANY">malicious1.example.com##comma##malicious2.example.com##comma##malicious3.example.com</DomainNameObj:Value>
					</cybox:Properties>
				</cybox:Object>
			</indicator:Observable>
		</stix:Indicator>
		<stix:Indicator xsi:type="indicator:IndicatorType" id="example:Indicator-2e20c5b2-56fa-46cd-9662-8f199c69d2d0" version="2.1.1">
			<indicator:Title>Sample Domain Watchlist Indicator</indicator:Title>
			<indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.0">Domain Watchlist</indicator:Type>
			<indicator:Description>Sample domain Indicator for this watchlist</indicator:Description>
			<indicator:Observable id="example:Observable-87c9a5bb-d005-4b3e-8081-99f720fad73c">
				<cybox:Object id="example:Object-12c760ba-cd2c-4f5d-a37d-18212eac7a39">
					<cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType" type="FQDN">
						<DomainNameObj:Value condition="Equals" apply_condition="ANY">malicious1.example.com##comma##malicious2.example.com##comma##malicious3.example.com</DomainNameObj:Value>
					</cybox:Properties>
				</cybox:Object>
			</indicator:Observable>
		</stix:Indicator>
		<stix:Indicator xsi:type="indicator:IndicatorType" id="example:Indicator-2e20c5b2-56fa-46cd-9662-8f199c69d2d1" version="2.1.1">
			<indicator:Description>Testing idref Observable lookup</indicator:Description>
			<indicator:Observable idref="example:Observable-12c760ba-cd2c-4f5d-a37d-18212eac7929"/>
		</stix:Indicator>
		<stix:Indicator xsi:type="indicator:IndicatorType" idref="example:Indicator-2e20c5b2-56fa-46cd-9662-8f199c69d2c9" timestamp="2014-02-20T10:00:00.000000Z" version="2.1.1" />
	</stix:Indicators>
</stix:STIX_Package>
"""

# The idref/timestamp pairs are equal.
TS_RESOLVES_XML = \
"""
<stix:STIX_Package
        xmlns:campaign="http://stix.mitre.org/Campaign-1"
        xmlns:cybox="http://cybox.mitre.org/cybox-2"
        xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
        xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
        xmlns:example="http://example.com"
        xmlns:indicator="http://stix.mitre.org/Indicator-2"
        xmlns:stix="http://stix.mitre.org/stix-1"
        xmlns:stixCommon="http://stix.mitre.org/common-1"
        xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" id="example:Package-b61d4796-b7f1-4300-bb72-4707e298ef21" version="1.1.1" timestamp="2015-04-14T15:24:19.416704+00:00">
    <stix:Indicators>
        <stix:Indicator id="example:indicator-1" timestamp="2015-04-14T15:24:19.416203+00:00" xsi:type='indicator:IndicatorType'>
            <indicator:Related_Campaigns>
                <indicator:Related_Campaign>
                    <stixCommon:Campaign idref="example:campaign-1" timestamp="2015-04-14T15:24:19.416203+00:00"/>
                </indicator:Related_Campaign>
            </indicator:Related_Campaigns>
        </stix:Indicator>
    </stix:Indicators>
    <stix:Campaigns>
        <stix:Campaign id="example:campaign-1" timestamp="2015-04-14T15:24:19.416203+00:00" xsi:type='campaign:CampaignType'/>
    </stix:Campaigns>
</stix:STIX_Package>
"""

# The idref/timestamp pairs don't resolve
TS_DOES_NOT_RESOLVE = \
"""
<stix:STIX_Package
        xmlns:campaign="http://stix.mitre.org/Campaign-1"
        xmlns:cybox="http://cybox.mitre.org/cybox-2"
        xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
        xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
        xmlns:example="http://example.com"
        xmlns:indicator="http://stix.mitre.org/Indicator-2"
        xmlns:stix="http://stix.mitre.org/stix-1"
        xmlns:stixCommon="http://stix.mitre.org/common-1"
        xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" id="example:Package-b61d4796-b7f1-4300-bb72-4707e298ef21" version="1.1.1" timestamp="2015-04-14T15:24:19.416704+00:00">
    <stix:Indicators>
        <stix:Indicator id="example:indicator-1" timestamp="2015-04-14T15:24:19.416203+00:00" xsi:type='indicator:IndicatorType'>
            <indicator:Related_Campaigns>
                <indicator:Related_Campaign>
                    <stixCommon:Campaign idref="example:campaign-1" timestamp="2015-04-14T15:24:19.416203+00:00"/>
                </indicator:Related_Campaign>
            </indicator:Related_Campaigns>
        </stix:Indicator>
    </stix:Indicators>
    <stix:Campaigns>
        <stix:Campaign id="example:campaign-1" timestamp="2014-01-01T00:00:01+00:00" xsi:type='campaign:CampaignType'/>
    </stix:Campaigns>
</stix:STIX_Package>
"""

# Same time, different timezones.
TS_TZ_RESOLVES = \
"""
<stix:STIX_Package
        xmlns:campaign="http://stix.mitre.org/Campaign-1"
        xmlns:cybox="http://cybox.mitre.org/cybox-2"
        xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
        xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
        xmlns:example="http://example.com"
        xmlns:indicator="http://stix.mitre.org/Indicator-2"
        xmlns:stix="http://stix.mitre.org/stix-1"
        xmlns:stixCommon="http://stix.mitre.org/common-1"
        xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" id="example:Package-b61d4796-b7f1-4300-bb72-4707e298ef21" version="1.1.1" timestamp="2015-04-14T15:24:19.416704+00:00">
    <stix:Indicators>
        <stix:Indicator id="example:indicator-1" timestamp="2015-04-14T15:24:19.416203+00:00" xsi:type='indicator:IndicatorType'>
            <indicator:Related_Campaigns>
                <indicator:Related_Campaign>
                    <stixCommon:Campaign idref="example:campaign-1" timestamp="2015-04-14T15:24:19.416203+00:00"/>
                </indicator:Related_Campaign>
            </indicator:Related_Campaigns>
        </stix:Indicator>
    </stix:Indicators>
    <stix:Campaigns>
        <stix:Campaign id="example:campaign-1" timestamp="2015-04-14T12:24:19.416203-03:00" xsi:type='campaign:CampaignType'/>
    </stix:Campaigns>
</stix:STIX_Package>
"""

class STIXBestPracticesTests(unittest.TestCase):

    @classmethod
    def setUp(cls):
        sio = StringIO(BP_INVALID_XML)
        cls.results = sdv.validate_best_practices(sio)

    def test_invalid_version(self):
        xml = StringIO(STIX_NO_VERSION_XML)
        func = sdv.validate_best_practices
        self.assertRaises(
            errors.InvalidSTIXVersionError, func, xml, version="INVALID"
        )

    def test_invalid_results(self):
        self.assertEqual(False, self.results.is_valid)

    def test_results_errors(self):
        num_errors = len(self.results.errors)
        self.assertTrue(num_errors > 0)

    def test_json(self):
        json_ = self.results.as_json()
        d1 = self.results.as_dict()
        d2 = json.loads(json_)
        self.assertEqual(d1, d2)

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

    def test_as_json(self):
        node = etree.Element("test")
        warning = bp.BestPracticeWarning(node)
        warning['foo'] = 'bar'
        json_ = warning.as_json()
        d = json.loads(json_)
        self.assertTrue('foo' in d)

    def test_as_dict(self):
        node = etree.Element("test")
        warning = bp.BestPracticeWarning(node)
        warning['foo'] = 'bar'
        d = warning.as_dict()
        self.assertTrue('foo' in d)


class BestPracticeTimestampTests(unittest.TestCase):
    def test_ts_resolves(self):
        sio = StringIO(TS_RESOLVES_XML)

        idref = "example:campaign-1"
        timestamp="2015-04-14T15:24:19.416203+00:00"

        resolves = common.idref_timestamp_resolves(
            root=sio,
            idref=idref,
            timestamp=timestamp,
            namespaces=common.get_stix_namespaces('1.1.1')
        )

        self.assertTrue(resolves)

    def test_ts_not_resolves(self):
        sio = StringIO(TS_DOES_NOT_RESOLVE)

        idref = "example:campaign-1"
        timestamp="2015-04-14T15:24:19.416203+00:00"

        resolves = common.idref_timestamp_resolves(
            root=sio,
            idref=idref,
            timestamp=timestamp,
            namespaces=common.get_stix_namespaces('1.1.1')
        )

        self.assertEqual(resolves, False)

    def test_ts_tz_resolves(self):
        root = utils.get_etree_root(StringIO(TS_TZ_RESOLVES))

        offset_resolves = common.idref_timestamp_resolves(
            root=root,
            idref="example:campaign-1",
            timestamp="2015-04-14T15:24:19.416203+00:00",
            namespaces=common.get_stix_namespaces('1.1.1')
        )

        zulu_resolves = common.idref_timestamp_resolves(
            root=root,
            idref="example:campaign-1",
            timestamp="2015-04-14T15:24:19.416203Z",
            namespaces=common.get_stix_namespaces('1.1.1')
        )

        self.assertTrue(zulu_resolves)
        self.assertTrue(offset_resolves)

    def test_id_pattern(self):
        pattern = bp.ID_PATTERN

        valid = [
            "sdv:foo-bar",
            "sdv:foo-123",
            "stix-validator:foo-123",
            "XYZ-AB:Package-01f2aa71-61a7-4829-9087-8ffa8202e60c"
        ]

        invalid = [
            "sdv:foobar",
            "sdv:foo/bar",
            "foo//bar",
        ]

        for s in valid:
            self.assertTrue(pattern.match(s))

        for s in invalid:
            self.assertEqual(None, pattern.match(s))


if __name__ == '__main__':
    unittest.main()
