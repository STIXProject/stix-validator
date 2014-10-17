# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import re
import collections
from lxml import etree

from sdv import ValidationResult
import sdv.utils as utils
import common as stix

TAG_XSI_TYPE = "{%s}type" % stix.NS_XSI

class BestPracticeWarningCollection(collections.MutableSequence):
    def __init__(self, name=None):
        self.name = name
        self._warnings = []

    def __getitem__(self, key):
        return self._warnings.__getitem__(key)

    def __setitem__(self, key, value):
        self._warnings.__setitem__(key, value)

    def __delitem__(self, key):
        self._warnings.__delitem__(key)

    def __len__(self):
        return len(self._warnings)

    def __nonzero__(self):
        return bool(self._warnings)

    def as_dict(self):
        d = {}

        if self._warnings:
            warnings = [x.as_dict() for x in self._warnings]
        else:
            warnings = None

        d[self.name] = warnings


class BestPracticeWarning(object):
    def __init__(self, node=None, message=None):
        self.message = message
        self.node = node
        self.id_ = node.attrib.get('id') if node else None
        self.idref = node.attrib.get('idref') if node else None
        self.line = node.sourceline if node else None
        self.tag = node.tag if node else None
        self._inner = {}

    def __unicode__(self):
        return unicode(self.message)

    def __str__(self):
        return unicode(self).encode('utf-8')

    def __getitem__(self, key):
        return self._inner.__getitem__(key)

    def __setitem__(self, key, value):
        self._inner.__setitem__(key, value)

    def as_dict(self):
        d = dict(self._inner.items())

        if self.id_:
            d['id_'] = self.id_

        if self.idref:
            d['idref'] = self.idref

        if self.tag:
            d['tag'] = self.tag

        if self.line:
            d['line'] = self.line

        if self.message:
            d['message'] = self.message

        return d


class BestPracticeValidationResult(ValidationResult):
    """Used for recording STIX best practice results.

    Attributes:
        warnings: TODO: write this

    """
    def __init__(self, is_valid=False):
        super(BestPracticeValidationResult, self).__init__(is_valid)
        self.warnings = None

    def as_dict(self):
        d = super(BestPracticeValidationResult, self).as_dict()

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
        to_check = (
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

        results = BestPracticeWarningCollection('Missing IDs')
        xpath = " | ".join("//%s" % x for x in to_check)
        nodes = root.xpath(xpath, namespaces=namespaces)

        for node in nodes:
            if not any(x in node.attrib for x in ('id', 'idref')):
                warning = BestPracticeWarning(node=node)
                results.append(warning)

        return results

    def check_id_format(self, root, namespaces, *args, **kwargs):
        '''
        Checks that the core STIX/CybOX constructs in the STIX instance
        document have ids and that each id is formatted as
        [ns_prefix]:[object-type]-[GUID].
        '''
        regex = re.compile(r'\w+:\w+-')

        to_check = (
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

        results = BestPracticeWarningCollection('ID Format')
        xpath = " | ".join("//%s" % x for x in to_check)
        nodes = root.xpath(xpath, namespaces=namespaces)

        for node in nodes:
            if 'id' not in node.attrib:
                continue

            id_ = node.attrib['id']
            if not regex.match(id_):
                result = BestPracticeWarning(node=node)
                results.append(result)

        return results

    def check_duplicate_ids(self, root, namespaces, *args, **kwargs):
        '''
        Checks for duplicate ids in the document.
        '''
        id_nodes = collections.defaultdict(list)

        for node in root.xpath("//*[@id]"):
            id_nodes[node.attrib['id']].append(node)

        results = BestPracticeWarningCollection('Duplicate IDs')
        for id, nodes in id_nodes.iteritems():
            if len(nodes) > 1:
                results.extend(BestPracticeWarning(node=x) for x in nodes)

        return results

    def check_idref_resolution(self, root, namespaces, *args, **kwargs):
        '''
        Checks that all idrefs resolve to a construct in the document

        '''

        idrefs  = root.xpath("//*[@idref]")
        ids     = root.xpath("//@id")

        warnings = [x for x in idrefs if x.attrib['idref'] not in ids]
        results = BestPracticeWarningCollection("Unresolved IDREFs")

        for warning in warnings:
            results.append(BestPracticeWarning(warning))

        return results

    def check_idref_with_content(self, root, namespaces, *args, **kwargs):
        '''
        Checks that constructs with idref set do not contain content
        '''

        def _is_empty(node):
            return bool(node.text) or len(node) > 0

        nodes = root.xpath("//*[@idref]")
        warnings = [BestPracticeWarning(x) for x in nodes if not _is_empty(x)]

        results = BestPracticeWarningCollection("IDREF with Content")
        for warning in warnings:
            results.append(warning)

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

        xpath = (
            "//%s:Indicator | //%s:Indicator" %
            (stix.PREFIX_STIX_CORE, stix.PREFIX_STIX_COMMON)
        )

        results = BestPracticeWarningCollection("Indicator Suggestions")
        indicators = root.xpath(xpath, namespaces=namespaces)

        for indicator in indicators:
            missing = []
            if 'idref' not in indicator.attrib:
                if indicator.find('{%s}Description' % ns_indicator) is None:
                    missing.append("Description")
                if indicator.find('{%s}Type' % ns_indicator) is None:
                    missing.append("Type")
                if indicator.find('{%s}Valid_Time_Position' % ns_indicator) is None:
                    missing.append('Valid_Time_Position')
                if indicator.find('{%s}Indicated_TTP' % ns_indicator) is None:
                    missing.append('Indicated_TTP')
                if indicator.find('{%s}Confidence' % ns_indicator) is None:
                    missing.append('Confidence')

                if missing:
                    warning = BestPracticeWarning(node=indicator)
                    warning['missing'] = missing
                    results.append(warning)

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
        results = BestPracticeWarningCollection("Root Element")

        if root.tag != "{%s}STIX_Package" % (ns_stix_core):
            warning = BestPracticeWarning(node=root)
            results.append(warning)

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

        def _latest_version(name):
            for version, vocabs in latest_map.iteritems():
                if name in vocabs:
                    return version


        results = BestPracticeWarningCollection("Vocab Suggestions")
        xpath = "//*[contains(@xsi:type, 'Vocab-')]" # assumption: STIX/CybOX convention: end Vocab names with "Vocab-<version#>"
        vocabs = root.xpath(xpath, namespaces=namespaces)

        for vocab in vocabs:
            name, version = re.split(
                ":|-", vocab.attrib[TAG_XSI_TYPE]
            )

            if name in latest_map.get(version):
                continue

            warning = BestPracticeWarning(node=vocab)
            warning['name'] = name
            warning['found version'] = version
            warning['latest version'] = _latest_version(name)
            results.append(warning)

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
        '''
        to_check = (
            '{0}:STIX_Package/{0}:STIX_Header'.format(stix.PREFIX_STIX_CORE),
            '{}:Campaign'.format(stix.PREFIX_STIX_CORE),
            '{}:Campaign'.format(stix.PREFIX_STIX_COMMON),
            '{}:Course_Of_Action'.format(stix.PREFIX_STIX_CORE),
            '{}:Course_Of_Action'.format(stix.PREFIX_STIX_COMMON),
            '{}:Exploit_Target'.format(stix.PREFIX_STIX_CORE),
            '{}:Exploit_Target'.format(stix.PREFIX_STIX_COMMON),
            '{}:Incident'.format(stix.PREFIX_STIX_CORE),
            '{}:Incident'.format(stix.PREFIX_STIX_COMMON),
            '{}:Indicator'.format(stix.PREFIX_STIX_CORE),
            '{}:Indicator'.format(stix.PREFIX_STIX_COMMON),
            '{}:Threat_Actor'.format(stix.PREFIX_STIX_COMMON),
            '{}:TTP'.format(stix.PREFIX_STIX_CORE),
            '{}:TTP'.format( stix.PREFIX_STIX_COMMON)
        )

        results = BestPracticeWarningCollection("Missing Titles")
        xpath = " | ".join("//%s" % x for x in to_check)
        nodes = root.xpath(xpath, namespaces=namespaces)

        for node in nodes:
            if 'idref' in node.attrib:
                continue

            if not any(etree.QName(x).localname == 'Title' for x in node):
                warning = BestPracticeWarning(node=node)
                results.append(warning)

        return results

    def check_marking_control_xpath(self, root, namespaces, *args, **kwargs):
        results = BestPracticeWarningCollection("Data Marking Control XPath")
        xpath = "//%s:Controlled_Structure" % stix.PREFIX_DATA_MARKING

        for elem in root.xpath(xpath, namespaces=namespaces):
            cs_xpath = elem.text
            message = None

            if not cs_xpath:
                message = "No XPath supplied"
            else:
                try:
                    res_set = elem.xpath(cs_xpath, namespaces=root.nsmap)
                    if len(res_set) == 0:
                        message = "Controll XPath does not return any results"
                except etree.XPathEvalError:
                    message = "Invalid XPath supplied"

            if message:
                result = BestPracticeWarning(node=elem, message=message)
                results.append(result)

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

        warnings = []
        rules = self.rules[None] + self.rules[version]

        for func in rules:
            results = func(root, namespaces, version=version)
            warnings.append(results)

        results = BestPracticeValidationResult()
        results.is_valid = not(any(warnings))
        results.warnings = warnings

        return results



