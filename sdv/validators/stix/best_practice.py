# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import re
import collections
import itertools
import distutils.version
from lxml import etree

from sdv import ValidationResult
import sdv.utils as utils
import common as stix


def rule(version=None):
    def decorator(func):
        func._is_rule = True
        func._version = version
        return func
    return decorator


class BestPracticeMeta(type):
    def __new__(metacls, name, bases, dict_):
        result = type.__new__(metacls, name, bases, dict_)

        result._rules = collections.defaultdict(list)
        rules =  (x for x in dict_.itervalues() if hasattr(x, '_is_rule'))

        for rule in rules:
            result._rules[rule._version].append(rule)

        return result


class BestPracticeWarning(collections.MutableMapping):
    def __init__(self, node=None, message=None):
        super(BestPracticeWarning, self).__init__()
        self._inner = {}
        self._node = node

        if message:
            self['message'] = message

        if node is not None:
            self['id'] = node.attrib.get('id')
            self['idref'] = node.attrib.get('idref')
            self['line'] = node.sourceline if node is not None else None
            self['tag'] = node.tag if node is not None else None

    def __unicode__(self):
        return unicode(self._inner)

    def __str__(self):
        return unicode(self).encode('utf-8')

    def __getitem__(self, key):
        return self._inner.__getitem__(key)

    def __delitem__(self, key):
        self._inner.__delitem__(key)

    def __setitem__(self, key, value):
        if value is None:
            return
        self._inner.__setitem__(key, value)

    def __len__(self):
        return self._inner.__len__()

    def __iter__(self):
        return self._inner.__iter__()

    @property
    def core_keys(self):
        core =  ('id', 'idref', 'line', 'tag')
        return [x for x in self.iterkeys() if x in core]

    @property
    def other_keys(self):
        return [x for x in self.iterkeys() if x not in self.core_keys]

    def as_dict(self):
        return dict(self.items())



class BestPracticeWarningCollection(collections.MutableSequence):
    def __init__(self, name):
        super(BestPracticeWarningCollection, self).__init__()
        self.name = name
        self._warnings = []

    def insert(self, idx, value):
        if not value:
            return
        self._warnings.insert(idx, value)

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
        if not self:
            return {}

        d = {self.name: [x.as_dict() for x in self]}

        return d

class BestPracticeValidationResult(ValidationResult, collections.MutableSequence):
    """Used for recording STIX best practice results.

    Attributes:
        warnings: TODO: write this

    """
    def __init__(self, is_valid=False):
        super(BestPracticeValidationResult, self).__init__(is_valid)
        self._warnings = []

    @ValidationResult.is_valid.getter
    def is_valid(self):
        return len(self) == 0


    def insert(self, idx, value):
        if not value:
            return

        self._warnings.insert(idx, value)

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
        d = ValidationResult.as_dict(self)

        if any(x for x in self):
            d['warnings'] = dict(
                itertools.chain(*(x.as_dict().items() for x in self if x))
            )

        return d

class STIXBestPracticeValidator(object):
    __metaclass__ = BestPracticeMeta

    def __init__(self):
       pass

    @rule()
    def check_id_presence(self, root, namespaces, *args, **kwargs):
        '''
        Checks that all major STIX/CybOX constructs have id attributes set.
        Constructs with idref attributes set should not have an id attribute
        and are thus omitted from the results.
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

    @rule()
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

    @rule()
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

    @rule()
    def check_idref_resolution(self, root, namespaces, *args, **kwargs):
        '''
        Checks that all idrefs resolve to a construct in the document

        '''

        idrefs  = root.xpath("//*[@idref]")
        ids     = root.xpath("//@id")

        warnings = [BestPracticeWarning(x) for x in idrefs if x.attrib['idref'] not in ids]
        results = BestPracticeWarningCollection("Unresolved IDREFs")
        results.extend(warnings)

        return results


    @rule()
    def check_idref_with_content(self, root, namespaces, *args, **kwargs):
        '''
        Checks that constructs with idref set do not contain content
        '''

        def _has_content(node):
            return bool(node.text) or len(node) > 0

        nodes = root.xpath("//*[@idref]")
        warnings = [BestPracticeWarning(x) for x in nodes if _has_content(x)]

        results = BestPracticeWarningCollection("IDREF with Content")
        results.extend(warnings)

        return results

    @rule()
    def check_indicator_practices(self, root, namespaces, *args, **kwargs):
        '''
        Looks for STIX Indicators that are missing a Description, Type,
        Valid_Time_Position, Indicated_TTP, and/or Confidence
        '''
        xpath = (
            "//%s:Indicator | //%s:Indicator" %
            (stix.PREFIX_STIX_CORE, stix.PREFIX_STIX_COMMON)
        )
        ns = namespaces[stix.PREFIX_STIX_INDICATOR]
        results = BestPracticeWarningCollection("Indicator Suggestions")
        indicators = root.xpath(xpath, namespaces=namespaces)

        for indicator in indicators:
            missing = []
            if 'idref' not in indicator.attrib:
                if indicator.find('{%s}Description' % ns) is None:
                    missing.append("Description")
                if indicator.find('{%s}Type' % ns) is None:
                    missing.append("Type")
                if indicator.find('{%s}Valid_Time_Position' % ns) is None:
                    missing.append('Valid_Time_Position')
                if indicator.find('{%s}Indicated_TTP' % ns) is None:
                    missing.append('Indicated_TTP')
                if indicator.find('{%s}Confidence' % ns) is None:
                    missing.append('Confidence')

                if missing:
                    warning = BestPracticeWarning(node=indicator)
                    warning['missing'] = missing
                    results.append(warning)

        return results

    @rule()
    def check_data_types(self, root, namespaces, *args, **kwargs):
        pass

    @rule()
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

    @rule()
    def check_indicator_patterns(self, root, namespaces, *args, **kwargs):
        pass

    @rule()
    def check_latest_vocabs(self, root, namespaces, *args, **kwargs):
        '''
        Checks that all STIX vocabs are using latest published versions.
        Triggers a warning if an out of date vocabulary is used.
        '''
        latest_map = {
            '1.0': (
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
            ),
            '1.0.1': (
                  "PlanningAndOperationalSupportVocab",
                  "EventTypeVocab" # cybox
            ),
            '1.1': (
                "IndicatorTypeVocab",
                "MotivationVocab",
                "ActionNameVocab", # cybox
                "ObjectRelationshipVocab", # cybox
                "ToolTypeVocab" # cybox
            ),
            '1.1.1': (
                "AvailabilityLossTypeVocab",
            )
        }

        def _latest_version(name):
            for version, vocabs in latest_map.iteritems():
                if name in vocabs:
                    return version


        results = BestPracticeWarningCollection("Vocab Suggestions")
        xpath = "//*[contains(@xsi:type, 'Vocab-')]" # assumption: STIX/CybOX convention: end Vocab names with "Vocab-<version#>"

        for vocab in root.xpath(xpath, namespaces=namespaces):
            type_ = re.split(":|-", vocab.attrib[stix.TAG_XSI_TYPE])
            name, version = type_[1], type_[2]

            if name in latest_map.get(version):
                continue

            warning = BestPracticeWarning(node=vocab)
            warning['vocab name'] = name
            warning['found version'] = version
            warning['latest version'] = _latest_version(name)
            results.append(warning)

        return results

    @rule()
    def check_content_versions(self, root, namespaces, *args, **kwargs):
        pass

    @rule(version='1.1')
    def check_timestamp_usage(self, root, namespaces, *args, **kwargs):
        pass

    @rule(version='1.1')
    def check_timestamp_timezone(self, root, namespaces, *args, **kwargs):
        pass

    @rule()
    def check_titles(self, root, namespaces, *args, **kwargs):
        '''
        Checks that all major STIX constructs have a Title element
        '''
        to_check = (
            '{0}:STIX_Package/{0}:STIX_Header'.format(stix.PREFIX_STIX_CORE),
            '{0}:Campaign'.format(stix.PREFIX_STIX_CORE),
            '{0}:Campaign'.format(stix.PREFIX_STIX_COMMON),
            '{0}:Course_Of_Action'.format(stix.PREFIX_STIX_CORE),
            '{0}:Course_Of_Action'.format(stix.PREFIX_STIX_COMMON),
            '{0}:Exploit_Target'.format(stix.PREFIX_STIX_CORE),
            '{0}:Exploit_Target'.format(stix.PREFIX_STIX_COMMON),
            '{0}:Incident'.format(stix.PREFIX_STIX_CORE),
            '{0}:Incident'.format(stix.PREFIX_STIX_COMMON),
            '{0}:Indicator'.format(stix.PREFIX_STIX_CORE),
            '{0}:Indicator'.format(stix.PREFIX_STIX_COMMON),
            '{0}:Threat_Actor'.format(stix.PREFIX_STIX_COMMON),
            '{0}:TTP'.format(stix.PREFIX_STIX_CORE),
            '{0}:TTP'.format( stix.PREFIX_STIX_COMMON)
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

    @rule()
    def check_marking_control_xpath(self, root, namespaces, *args, **kwargs):
        results = BestPracticeWarningCollection("Data Marking Control XPath")
        xpath = "//%s:Controlled_Structure" % stix.PREFIX_DATA_MARKING

        def _test_xpath(node, xpath):
            try:
                res_set = elem.xpath(cs_xpath, namespaces=root.nsmap)
                if len(res_set) == 0:
                    return "Control XPath does not return any results"
            except etree.XPathEvalError:
                return "Invalid XPath supplied"

        for elem in root.xpath(xpath, namespaces=namespaces):
            cs_xpath = elem.text
            if not cs_xpath:
                message = "Empty Control XPath"
            else:
                message = _test_xpath(elem, cs_xpath)

            if message:
                result = BestPracticeWarning(node=elem, message=message)
                results.append(result)

        return results

    def _get_stix_construct_versions(self, version):
        pass


    def _get_vocabs(self, version):
        pass


    def _get_rules(self, version):
        sv = distutils.version.StrictVersion
        checks = self._rules.iteritems()
        rules = itertools.chain(
            *(funcs for (x, funcs) in checks if not x or sv(x) <= sv(version))
        )

        return rules

    def _run_rules(self, root, version):
        namespaces = stix.get_stix_namespaces(version)
        results = BestPracticeValidationResult()
        rules = self._get_rules(version)

        for func in rules:
            result = func(self, root, namespaces, version=version)
            results.append(result)

        return results


    def validate(self, doc, version=None):
        root = utils.get_etree_root(doc)

        try:
            version = version or stix.get_version(doc)
        except KeyError:
            raise stix.UnknownVersionError(
                "Document did not contain a 'version' attribute"
            )

        if version not in stix.STIX_VERSIONS:
            raise stix.InvalidVersionError(
                "Cannot run rules: '%s' is an invalid STIX version" % version,
                expected=stix.STIX_VERSIONS,
                found=version
            )

        results = self._run_rules(root, version)
        return results

