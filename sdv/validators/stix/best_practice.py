# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import re
from collections import defaultdict
from lxml import etree

from sdv import ValidationResults
import sdv.utils as utils
import common as stix


class BestPracticeResults(ValidationResults):
    def __init__(self):
        super(BestPracticeResults, self).__init__()
        self.warnings = None


    def as_dict(self):
        d = super(BestPracticeResults, self).as_dict()

        if self.warnings:
            d['warnings'] = self.warnings

        return d

class STIXBestPracticeValidator(object):
    def __init__(self):
        # Best Practice rule dictionary
        # STIX version => function list
        # None means all versions
        self.rules = {
            None: (
                self.check_id_presence, self.check_id_format,
                self.check_duplicate_ids, self.check_idref_resolution,
                self.check_idref_with_content, self.check_indicator_practices,
                self.check_indicator_patterns,
                self.check_root_element,
                self.check_titles, self.check_marking_control_xpath,
                self.check_latest_vocabs
            ),
            '1.1': (
                self.check_timestamp_usage, self.check_timestamp_timezone
            ),
            '1.1.1': (
                self.check_timestamp_usage, self.check_timestamp_timezone
            )
        }

    def check_id_presence(self, root, namespaces, *args, **kwargs):
        '''
        Checks that all major STIX/CybOX constructs have id attributes set.
        Constructs with idref attributes set should not have an id attribute
        and are thus omitted from the results.

        :param root:
        :param namespaces:
        :param args:
        :param kwargs:
        :return:
        '''
        elements_to_check = (
             '%s:STIX_Package' % stix.PREFIX_STIX_CORE,
             '%s:Campaign' % stix.PREFIX_STIX_CORE,
             '%s:Campaign' % stix.PREFIX_STIX_COMMON,
             '%s:Course_Of_Action' % stix.PREFIX_STIX_CORE,
             '%s:Course_Of_Action' % stix.PREFIX_STIX_COMMON,
             '%s:Exploit_Target' % stix.PREFIX_STIX_CORE,
             '%s:Exploit_Target' % stix.PREFIX_STIX_COMMON,
             '%s:Incident' % stix.PREFIX_STIX_CORE,
             '%s:Incident' % stix.PREFIX_STIX_COMMON,
             '%s:Indicator' % stix.PREFIX_STIX_CORE,
             '%s:Indicator' % stix.PREFIX_STIX_COMMON,
             '%s:Threat_Actor' % stix.PREFIX_STIX_COMMON,
             '%s:TTP' % stix.PREFIX_STIX_CORE,
             '%s:TTP' % stix.PREFIX_STIX_COMMON,
             '%s:Observable' % stix.PREFIX_CYBOX_CORE,
             '%s:Object' % stix.PREFIX_CYBOX_CORE,
             '%s:Event' % stix.PREFIX_CYBOX_CORE,
             '%s:Action' % stix.PREFIX_CYBOX_CORE
        )

        results = defaultdict(list)
        for tag in elements_to_check:
            xpath = "//%s" % tag
            for element in root.xpath(xpath, namespaces=namespaces):
                if 'idref' not in element.attrib and 'id' not in element.attrib:
                    result = {'tag': element.tag,
                              'line_number': element.sourceline}

                    results['missing_ids'].append(result)

        return results

    def check_id_format(self, root, namespaces, *args, **kwargs):
        '''
        Checks that the core STIX/CybOX constructs in the STIX instance
        document have ids and that each id is formatted as
        [ns_prefix]:[object-type]-[GUID].
        :param root:
        :param namespaces:
        :param args:
        :param kwargs:
        :return:
        '''
        regex = re.compile(r'\w+:\w+-')

        elements_to_check = (
             '%s:STIX_Package' % stix.PREFIX_STIX_CORE,
             '%s:Campaign' % stix.PREFIX_STIX_CORE,
             '%s:Campaign' % stix.PREFIX_STIX_COMMON,
             '%s:Course_Of_Action' % stix.PREFIX_STIX_CORE,
             '%s:Course_Of_Action' % stix.PREFIX_STIX_COMMON,
             '%s:Exploit_Target' % stix.PREFIX_STIX_CORE,
             '%s:Exploit_Target' % stix.PREFIX_STIX_COMMON,
             '%s:Incident' % stix.PREFIX_STIX_CORE,
             '%s:Incident' % stix.PREFIX_STIX_COMMON,
             '%s:Indicator' % stix.PREFIX_STIX_CORE,
             '%s:Indicator' % stix.PREFIX_STIX_COMMON,
             '%s:Threat_Actor' % stix.PREFIX_STIX_COMMON,
             '%s:TTP' % stix.PREFIX_STIX_CORE,
             '%s:TTP' % stix.PREFIX_STIX_COMMON,
             '%s:Observable' % stix.PREFIX_CYBOX_CORE,
             '%s:Object' % stix.PREFIX_CYBOX_CORE,
             '%s:Event' % stix.PREFIX_CYBOX_CORE,
             '%s:Action' % stix.PREFIX_CYBOX_CORE
        )

        results = defaultdict(list)
        for tag in elements_to_check:
            xpath = "//%s" % tag
            for element in root.xpath(xpath, namespaces=namespaces):
                if 'id' in element.attrib:
                    id_ = element.attrib['id']
                    if not regex.match(id_):
                        result = {'tag': element.tag,
                                  'id': id_,
                                  'line_number': element.sourceline}

                        results['id_format'].append(result)

        return results

    def check_duplicate_ids(self, root, namespaces, *args, **kwargs):
        '''
        Checks for duplicate ids in the document.
        :param root:
        :param namespaces:
        :param args:
        :param kwargs:
        :return:
        '''
        dup_dict = {}
        results = {}
        dict_id_nodes = defaultdict(list)
        xpath_all_nodes_with_ids = "//*[@id]"

        all_nodes_with_ids = root.xpath(xpath_all_nodes_with_ids)
        for node in all_nodes_with_ids:
            dict_id_nodes[node.attrib['id']].append(node)

        for id, node_list in dict_id_nodes.iteritems():
            if len(node_list) > 1:
                dup_dict[id] = [{'tag': node.tag,
                                 'line_number': node.sourceline}
                                for node in node_list]

        if dup_dict:
            results['duplicate_ids'] = dup_dict

        return results

    def check_idref_resolution(self, root, namespaces, *args, **kwargs):
        '''
        Checks that all idrefs resolve to a construct in the document
        :param root:
        :param namespaces:
        :param args:
        :param kwargs:
        :return:
        '''
        xpath_all_idrefs = "//*[@idref]"
        xpath_all_ids = "//@id"

        all_idrefs = root.xpath(xpath_all_idrefs)
        all_ids = root.xpath(xpath_all_ids)

        results = defaultdict(list)
        for element in all_idrefs:
            if element.attrib['idref'] not in all_ids:
                result = {'tag': element.tag,
                          'idref': element.attrib['idref'],
                          'line_number': element.sourceline}

                results['unresolved_idrefs'].append(result)

        return results

    def check_idref_with_content(self, root, namespaces, *args, **kwargs):
        '''
        Checks that constructs with idref set do not contain content
        :param root:
        :param namespaces:
        :param args:
        :param kwargs:
        :return:
        '''
        xpath = "//*[@idref]"
        elements = root.xpath(xpath)
        results = defaultdict(list)

        for element in elements:
            if element.text or len(element) > 0:
                result = {'tag': element.tag,
                          'idref': element.attrib['idref'],
                          'line_number': element.sourceline}
                results['idref_with_content'].append(result)

        return results

    def check_indicator_practices(self, root, namespaces, *args, **kwargs):
        '''
        Looks for STIX Indicators that are missing a Description, Type,
        Valid_Time_Position, Indicated_TTP, and/or Confidence
        :param root:
        :param namespaces:
        :param args:
        :param kwargs:
        :return:
        '''
        ns_indicator = namespaces[stix.PREFIX_STIX_INDICATOR]
        xpath = "//%s:Indicator | //%s:Indicator" % (stix.PREFIX_STIX_CORE,
                                                     stix.PREFIX_STIX_COMMON)
        results = {}
        list_indicators = []
        indicators = root.xpath(xpath, namespaces=namespaces)
        for indicator in indicators:
            dict_indicator = defaultdict(list)
            if 'idref' not in indicator.attrib:     # if this is not an idref
                                                    # node, look at its content
                if indicator.find('{%s}Description' % ns_indicator) is None:
                    dict_indicator['missing'].append('Description')
                if indicator.find('{%s}Type' % ns_indicator) is None:
                    dict_indicator['missing'].append('Type')
                if indicator.find('{%s}Valid_Time_Position' % ns_indicator) is None:
                    dict_indicator['missing'].append('Valid_Time_Position')
                if indicator.find('{%s}Indicated_TTP' % ns_indicator) is None:
                    dict_indicator['missing'].append('TTP')
                if indicator.find('{%s}Confidence' % ns_indicator) is None:
                    dict_indicator['missing'].append('Confidence')

                if dict_indicator:
                    dict_indicator['id'] = indicator.attrib.get('id')
                    dict_indicator['line_number'] = indicator.sourceline
                    list_indicators.append(dict_indicator)

        if list_indicators:
            results['indicator_suggestions'] = list_indicators

        return results

    def check_data_types(self, root, namespaces, *args, **kwargs):
        return {}

    def check_root_element(self, root, namespaces, *args, **kwargs):
        '''
        Checks that the root element is a STIX_Package
        :param root:
        :param namespaces:
        :param args:
        :param kwargs:
        :return:
        '''
        ns_stix_core = namespaces[stix.PREFIX_STIX_CORE]
        results = {}

        if root.tag != "{%s}STIX_Package" % (ns_stix_core):
            result = {}
            result['tag'] = root.tag
            result['line_number'] = root.sourceline
            results['root_element'] = result

        return results

    def check_indicator_patterns(self, root, namespaces, *args, **kwargs):
        return {}

    def check_latest_vocabs(self, root, namespaces, *args, **kwargs):
        '''
        Checks that all STIX vocabs are using latest published versions.
        Triggers a warning if an out of date vocabulary is used.
        :param root:
        :param namespaces:
        :param args:
        :param kwargs:
        :return:
        '''
        latest_map = {
            '1.0': [
                    "AssetTypeVocab",
                    "AttackerInfrastructureTypeVocab",
                    "AttackerToolTypeVocab",
                    "COAStageVocab",
                    "CampaignStatusVocab",
                    "CourseOfActionTypeVocab",
                    "DiscoveryMethodVocab",
                    "HighMediumLowVocab",
                    "ImpactQualificationVocab",
                    "ImpactRatingVocab",
                    "IncidentCategoryVocab",
                    "IncidentEffectVocab",
                    "IncidentStatusVocab",
                    "InformationSourceRoleVocab",
                    "InformationTypeVocab",
                    "IntendedEffectVocab",
                    "LocationClassVocab",
                    "LossDurationVocab",
                    "LossPropertyVocab",
                    "MalwareTypeVocab",
                    "ManagementClassVocab",
                    "OwnershipClassVocab",
                    "PackageIntentVocab",
                    "SecurityCompromiseVocab",
                    "SystemTypeVocab",
                    "ThreatActorSophisticationVocab",
                    "ThreatActorTypeVocab",
                    "ActionArgumentNameVocab", # cybox
                    "ActionObjectAssociationTypeVocab", #cybox
                    "ActionRelationshipTypeVocab", # cybox
                    "ActionTypeVocab", # cybox
                    "CharacterEncodingVocab", # cybox
                    "EventTypeVocab", # cybox
                    "HashNameVocab", # cybox
                    "InformationSourceTypeVocab", # cybox
                    "ObjectStateVocab" # cybox
                    ],
            '1.0.1': [
                      "PlanningAndOperationalSupportVocab",
                      "EventTypeVocab" # cybox
                      ],
            '1.1': ["IndicatorTypeVocab",
                    "MotivationVocab",
                    "ActionNameVocab", # cybox
                    "ObjectRelationshipVocab", # cybox
                    "ToolTypeVocab" # cybox
                    ],
            '1.1.1': [
                      "AvailabilityLossTypeVocab"
                      ]
        }

        results = {}
        list_vocabs = []
        xpath = "//*[contains(@xsi:type, 'Vocab-')]" # assumption: STIX/CybOX convention: end Vocab names with "Vocab-<version#>"
        vocabs = root.xpath(xpath, namespaces=namespaces)
        for vocab in vocabs:
            xsi_type = re.split(":|-", vocab.attrib["{%s}type" % namespaces[stix.PREFIX_XSI]])
            if not xsi_type[1] in latest_map.get(xsi_type[2]):
                dict_vocab = defaultdict(list)
                dict_vocab['line_number'] = vocab.sourceline
                dict_vocab['out_of_date'] = xsi_type[1]
                dict_vocab['given_version'] = xsi_type[2]
                for version_num in latest_map:
                    if xsi_type[1] in latest_map[version_num]:
                        dict_vocab['newest_version'] = version_num
                        break
                list_vocabs.append(dict_vocab)

        if list_vocabs: # only add list to results if there are entries
            results['vocab_suggestions'] = list_vocabs
        return results

    def check_content_versions(self, root, namespaces, *args, **kwargs):
        return {}

    def check_timestamp_usage(self, root, namespaces, *args, **kwargs):
        return {}

    def check_timestamp_timezone(self, root, namespaces, *args, **kwargs):
        return {}

    def check_titles(self, root, namespaces, *args, **kwargs):
        '''
        Checks that all major STIX constructs have a Title element
        :param root:
        :param namespaces:
        :param args:
        :param kwargs:
        :return:
        '''
        elements_to_check = (
            '%s:STIX_Package/%s:STIX_Header' % (stix.PREFIX_STIX_CORE,
                                                stix.PREFIX_STIX_CORE),
            '%s:Campaign' % stix.PREFIX_STIX_CORE,
            '%s:Campaign' % stix.PREFIX_STIX_COMMON,
            '%s:Course_Of_Action' % stix.PREFIX_STIX_CORE,
            '%s:Course_Of_Action' % stix.PREFIX_STIX_COMMON,
            '%s:Exploit_Target' % stix.PREFIX_STIX_CORE,
            '%s:Exploit_Target' % stix.PREFIX_STIX_COMMON,
            '%s:Incident' % stix.PREFIX_STIX_CORE,
            '%s:Incident' % stix.PREFIX_STIX_COMMON,
            '%s:Indicator' % stix.PREFIX_STIX_CORE,
            '%s:Indicator' % stix.PREFIX_STIX_COMMON,
            '%s:Threat_Actor' % stix.PREFIX_STIX_COMMON,
            '%s:TTP' % stix.PREFIX_STIX_CORE,
            '%s:TTP' % stix.PREFIX_STIX_COMMON,
        )

        results = defaultdict(list)
        for tag in elements_to_check:
            xpath = "//%s" % tag
            for element in root.xpath(xpath, namespaces=namespaces):
                if 'idref' not in element.attrib:
                    found_title = False
                    for child in element:
                        if child.tag.endswith("}Title"):
                            found_title = True
                            break

                    if not found_title:
                        result = {'tag': element.tag,
                                  'line_number': element.sourceline,
                                  'id': element.attrib.get('id')}
                        results['missing_titles'].append(result)

        return results

    def check_marking_control_xpath(self, root, namespaces, *args, **kwargs):
        results = defaultdict(list)
        xpath = "//%s:Controlled_Structure" % stix.PREFIX_DATA_MARKING
        for elem in root.xpath(xpath, namespaces=namespaces):
            cs_xpath = elem.text
            result = {'problem': None, 'line_number': elem.sourceline }
            if not cs_xpath:
                result['problem'] = "No XPath supplied"
            else:
                try:
                    res_set = elem.xpath(cs_xpath, namespaces=root.nsmap)
                    if not res_set:
                        result['problem'] = "XPath does not return any results"
                except etree.XPathEvalError as e:
                    result['problem'] = "Invalid XPath supplied"
            if result['problem']:
                results['marking_control_xpath_issues'].append(result)
        return results

    def _get_stix_construct_versions(self, version):
        pass

    def _get_vocabs(self, version):
        pass


    def validate(self, doc, version=None):
        root = utils.get_etree_root(doc)

        try:
            version = version or stix.get_version(doc)
        except KeyError:
            raise stix.UnknownVersionError(
                "Document did not contain a 'version' attribute"
            )

        if version not in self.rules:
            raise stix.InvalidVersionError(
                "Unable to determine rules for STIX version %s" % version,
                expected=[x for x in self.rules.keys() if x],
                found=version
            )

        namespaces = stix.get_stix_namespaces(version)
        # allowed_vocabs = self._get_vocabs(version)
        # allowed_construct_versions = self._get_construct_versions(version)

        warnings = {}
        rules = self.rules[None] + self.rules[version]

        for func in rules:
            results = func(root, namespaces, version=version)
            warnings.update(results)

        results = BestPracticeResults()
        results.is_valid = not(warnings)
        results.warnings = warnings

        return results



