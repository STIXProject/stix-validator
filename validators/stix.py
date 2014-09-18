# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import re
from collections import defaultdict
from lxml import etree
import xlrd

from .xml_schema import XmlSchemaValidator
from .schematron import SchematronValidator

PREFIX_XSI = 'xsi'
PREFIX_STIX_CORE = 'stix-core'
PREFIX_STIX_COMMON = 'stix-common'
PREFIX_STIX_CAMPAIGN = 'stix-campaign'
PREFIX_STIX_COA = 'stix-coa'
PREFIX_STIX_EXPLOIT_TARGET = 'stix-et'
PREFIX_STIX_INDICATOR = 'stix-indicator'
PREFIX_STIX_INCIDENT = 'stix-incident'
PREFIX_STIX_THREAT_ACTOR = 'stix-ta'
PREFIX_STIX_VOCABS = 'stix-vocabs'
PREFIX_DATA_MARKING = 'data-marking'
PREFIX_CYBOX_CORE = 'cybox-core'
PREFIX_CYBOX_COMMON = 'cybox-common'
PREFIX_CYBOX_VOCABS = 'cybox-vocabs'


class UnknownVersionException(Exception):
    pass


def get_stix_namespaces(version):
    if version in ('1.0', '1.0.1', '1.1', '1.1.1'):
        d = {PREFIX_XSI: "http://www.w3.org/2001/XMLSchema-instance",
             PREFIX_STIX_CORE: 'http://stix.mitre.org/stix-1',
             PREFIX_STIX_COMMON: 'http://stix.mitre.org/common-1',
             PREFIX_STIX_CAMPAIGN: 'http://stix.mitre.org/Campaign-1',
             PREFIX_STIX_COA: 'http://stix.mitre.org/CourseOfAction-1',
             PREFIX_STIX_EXPLOIT_TARGET: 'http://stix.mitre.org/ExploitTarget-1',
             PREFIX_STIX_INDICATOR: 'http://stix.mitre.org/Indicator-2',
             PREFIX_STIX_INCIDENT: 'http://stix.mitre.org/Incident-1',
             PREFIX_STIX_THREAT_ACTOR: 'http://stix.mitre.org/ThreatActor-1',
             PREFIX_STIX_VOCABS: 'http://stix.mitre.org/default_vocabularies-1',
             PREFIX_DATA_MARKING: 'http://data-marking.mitre.org/Marking-1',
             PREFIX_CYBOX_CORE: 'http://cybox.mitre.org/cybox-2',
             PREFIX_CYBOX_COMMON: 'http://cybox.mitre.org/common-2',
             PREFIX_CYBOX_VOCABS: 'http://cybox.mitre.org/default_vocabularies-2'}
    else:
        raise UnknownVersionException("Unable to determine namespaces for "
                                      "version %s" % version)

    return d


def get_document_version(doc):
    root = get_root(doc)
    xpath = "./@version"

    version = root.xpath(xpath)
    if version is None or len(version) == 0:
        return None

    return version[0]


def get_root(doc):
    if isinstance(doc, etree._Element):
        root = doc
    elif isinstance(doc, etree._ElementTree):
        root = doc.getroot()
    else:
        parser = etree.ETCompatXMLParser(huge_tree=True)
        tree = etree.parse(doc, parser=parser)
        root = tree.getroot()

    return root


class STIXBestPracticeValidator(object):
    def __init__(self):
        # Best Practice rule dictionary
        # STIX version => function list
        # None means all versions
        self.rules = {
            None: (self.check_id_presence, self.check_id_format,
                   self.check_duplicate_ids, self.check_idref_resolution,
                   self.check_idref_with_content, self.check_indicator_practices,
                   self.check_indicator_patterns,
                   self.check_root_element,
                   self.check_titles, self.check_marking_control_xpath,
                   self.check_latest_vocabs),
            '1.1': (self.check_timestamp_usage, self.check_timestamp_timezone),
            '1.1.1': (self.check_timestamp_usage, self.check_timestamp_timezone)
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
             '%s:STIX_Package' % PREFIX_STIX_CORE,
             '%s:Campaign' % PREFIX_STIX_CORE,
             '%s:Campaign' % PREFIX_STIX_COMMON,
             '%s:Course_Of_Action' % PREFIX_STIX_CORE,
             '%s:Course_Of_Action' % PREFIX_STIX_COMMON,
             '%s:Exploit_Target' % PREFIX_STIX_CORE,
             '%s:Exploit_Target' % PREFIX_STIX_COMMON,
             '%s:Incident' % PREFIX_STIX_CORE,
             '%s:Incident' % PREFIX_STIX_COMMON,
             '%s:Indicator' % PREFIX_STIX_CORE,
             '%s:Indicator' % PREFIX_STIX_COMMON,
             '%s:Threat_Actor' % PREFIX_STIX_COMMON,
             '%s:TTP' % PREFIX_STIX_CORE,
             '%s:TTP' % PREFIX_STIX_COMMON,
             '%s:Observable' % PREFIX_CYBOX_CORE,
             '%s:Object' % PREFIX_CYBOX_CORE,
             '%s:Event' % PREFIX_CYBOX_CORE,
             '%s:Action' % PREFIX_CYBOX_CORE
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
             '%s:STIX_Package' % PREFIX_STIX_CORE,
             '%s:Campaign' % PREFIX_STIX_CORE,
             '%s:Campaign' % PREFIX_STIX_COMMON,
             '%s:Course_Of_Action' % PREFIX_STIX_CORE,
             '%s:Course_Of_Action' % PREFIX_STIX_COMMON,
             '%s:Exploit_Target' % PREFIX_STIX_CORE,
             '%s:Exploit_Target' % PREFIX_STIX_COMMON,
             '%s:Incident' % PREFIX_STIX_CORE,
             '%s:Incident' % PREFIX_STIX_COMMON,
             '%s:Indicator' % PREFIX_STIX_CORE,
             '%s:Indicator' % PREFIX_STIX_COMMON,
             '%s:Threat_Actor' % PREFIX_STIX_COMMON,
             '%s:TTP' % PREFIX_STIX_CORE,
             '%s:TTP' % PREFIX_STIX_COMMON,
             '%s:Observable' % PREFIX_CYBOX_CORE,
             '%s:Object' % PREFIX_CYBOX_CORE,
             '%s:Event' % PREFIX_CYBOX_CORE,
             '%s:Action' % PREFIX_CYBOX_CORE
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
        ns_indicator = namespaces[PREFIX_STIX_INDICATOR]
        xpath = "//%s:Indicator | //%s:Indicator" % (PREFIX_STIX_CORE,
                                                     PREFIX_STIX_COMMON)
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
        ns_stix_core = namespaces[PREFIX_STIX_CORE]
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
            '1.0': ["AssetTypeVocab",
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
                    "ThreatActorTypeVocab"],
            '1.0.1': ["PlanningAndOperationalSupportVocab"],
            '1.1': ["IndicatorTypeVocab", "MotivationVocab"],
            '1.1.1': ["AvailabilityLossTypeVocab"]
        }
        
        results = {}
        list_vocabs = []
        xpath = "//*[starts-with(@xsi:type, 'stixVocabs:')]"
        vocabs = root.xpath(xpath, namespaces=namespaces)
        for vocab in vocabs:
            xsi_type = re.split(":|-", vocab.attrib["{%s}type" % namespaces[PREFIX_XSI]])
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
            '%s:STIX_Package/%s:STIX_Header' % (PREFIX_STIX_CORE,
                                                PREFIX_STIX_CORE),
            '%s:Campaign' % PREFIX_STIX_CORE,
            '%s:Campaign' % PREFIX_STIX_COMMON,
            '%s:Course_Of_Action' % PREFIX_STIX_CORE,
            '%s:Course_Of_Action' % PREFIX_STIX_COMMON,
            '%s:Exploit_Target' % PREFIX_STIX_CORE,
            '%s:Exploit_Target' % PREFIX_STIX_COMMON,
            '%s:Incident' % PREFIX_STIX_CORE,
            '%s:Incident' % PREFIX_STIX_COMMON,
            '%s:Indicator' % PREFIX_STIX_CORE,
            '%s:Indicator' % PREFIX_STIX_COMMON,
            '%s:Threat_Actor' % PREFIX_STIX_COMMON,
            '%s:TTP' % PREFIX_STIX_CORE,
            '%s:TTP' % PREFIX_STIX_COMMON,
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
        return {}

    def _get_stix_construct_versions(self, version):
        pass

    def _get_vocabs(self, version):
        pass

    def validate(self, doc, version=None):
        try:
            root = get_root(doc)
            version = version or get_document_version(root)

            if not version:
                raise UnknownVersionException("Unable to determine STIX version")

            if version not in self.rules:
                raise UnknownVersionException("Unable to determine rules for "
                                              "STIX version %s" % version)

            namespaces = get_stix_namespaces(version)
            # allowed_vocabs = self._get_vocabs(version)
            # allowed_construct_versions = self._get_construct_versions(version)

            warnings = {}
            rules = self.rules[None] + self.rules[version]

            for func in rules:
                results = func(root, namespaces, version=version)
                warnings.update(results)

            results = {}
            if warnings:
                results['result'] = False
                results['warnings'] = warnings
            else:
                results['result'] = True
                
            return results
        
        except Exception as ex:
            return {'result': False, 'fatal': str(ex)}


class STIXSchemaValidator(object):
    def __init__(self, schemas):
        self.xml_schema_validators = self._get_validators(schemas)

    def _error(self, msg):
        return {'result': False,
                'errors': [msg]}

    def _get_validators(self, schemas):
        validators = {None: XmlSchemaValidator()}

        for version, location in schemas.iteritems():
            validator = XmlSchemaValidator(location)
            validators[version] = validator

        return validators

    def validate(self, doc, version=None, schemaloc=False):
        try:
            root = get_root(doc)
            version = version or get_document_version(root)

            if not (version or schemaloc):
                raise UnknownVersionException(
                    "Unable to validate instance document. STIX version not "
                    "found in instance document and not supplied to validate() "
                    "method")

            if schemaloc:
                xml_schema_validator = self.xml_schema_validators[None]
            else:
                if version not in self.xml_schema_validators:
                    raise UnknownVersionException("No schemas for STIX version "
                            "%s" % version)

                xml_schema_validator = self.xml_schema_validators[version]

            results = xml_schema_validator.validate(root, schemaloc)
        except Exception as ex:
            results = self._error(str(ex))

        return results


class STIXProfileValidator(SchematronValidator):
    def __init__(self, profile_fn):
        '''Initializes an instance of STIXFrofileValidator.'''
        profile = self._open_profile(profile_fn)
        schema = self._parse_profile(profile)

        super(STIXProfileValidator, self).__init__(schematron=schema)

    def _build_rule_dict(self, worksheet):
        '''Builds a dictionary representation of the rules defined by a STIX
        profile document.'''
        d = defaultdict(list)
        for i in xrange(1, worksheet.nrows):
            if not any(self._get_cell_value(worksheet, i, x)
                       for x in xrange(0, worksheet.ncols)):  # empty row
                continue
            if not self._get_cell_value(worksheet, i, 1):  # assume this is a label row
                context = self._get_cell_value(worksheet, i, 0)
                continue

            field = self._get_cell_value(worksheet, i, 0)
            occurrence = self._get_cell_value(worksheet, i, 1).lower()
            xsi_types = self._get_cell_value(worksheet, i, 3)
            allowed_values = self._get_cell_value(worksheet, i, 4)

            list_xsi_types = [x.strip() for x in xsi_types.split(',')] \
                if xsi_types else []
            list_allowed_values = [x.strip() for x in allowed_values.split(',')] \
                if allowed_values else []

            if (occurrence in ('required', 'prohibited') or
                    len(list_xsi_types) > 0 or
                    len(list_allowed_values) > 0):  # ignore rows with no rules
                d[context].append({'field': field,
                                   'occurrence': occurrence,
                                   'xsi_types': list_xsi_types,
                                   'allowed_values': list_allowed_values})

        return d

    def _add_root_test(self, pattern, nsmap):
        '''
        Adds a root-level test that requires the root element of a STIX
        document be a STIX_Package.
        '''
        ns_stix = "http://stix.mitre.org/stix-1"
        rule_element = self._add_element(pattern, "rule", context="/")
        text = "The root element must be a STIX_Package instance"
        test = "%s:STIX_Package" % nsmap.get(ns_stix, 'stix')
        element = etree.XML('<assert xmlns="%s" test="%s" role="error">%s '
                            '[<value-of select="saxon:line-number()"/>]</assert> '
                            % (self.NS_SCHEMATRON, test, text))
        rule_element.append(element)

    def _add_required_test(self, rule_element, entity_name, context):
        '''Adds a test to the rule element checking for the presence of a
        required STIX field.'''
        entity_path = "%s/%s" % (context, entity_name)
        text = "%s is required by this profile" % (entity_path)
        test = entity_name
        element = etree.XML('<assert xmlns="%s" test="%s" role="error">%s '
                            '[<value-of select="saxon:line-number()"/>]</assert> '
                            % (self.NS_SCHEMATRON, test, text))
        rule_element.append(element)

    def _add_prohibited_test(self, rule_element, entity_name, context):
        '''Adds a test to the rule element checking for the presence of a prohibited STIX field.'''
        entity_path = "%s/%s" % (context, entity_name) if entity_name.startswith("@") else context
        text = "%s is prohibited by this profile" % (entity_path)
        test_field = entity_name if entity_name.startswith("@") else "true()"
        element = etree.XML('<report xmlns="%s" test="%s" role="error">%s '
                            '[<value-of select="saxon:line-number()"/>]</report> '
                            % (self.NS_SCHEMATRON, test_field, text))
        rule_element.append(element)

    def _add_allowed_xsi_types_test(self, rule_element, context,
                                    entity_name, allowed_xsi_types):
        '''Adds a test to the rule element which corresponds to values found in the Allowed Implementations
        column of a STIX profile document.'''
        entity_path = "%s/%s" % (context, entity_name)

        if allowed_xsi_types:
            test = " or ".join("@xsi:type='%s'" % (x) for x in allowed_xsi_types)
            text = 'The allowed xsi:types for %s are %s' % (entity_path,
                                                            allowed_xsi_types)
            element = etree.XML('<assert xmlns="%s" test="%s" role="error">%s '
                                '[<value-of select="saxon:line-number()"/>]</assert> '
                                % (self.NS_SCHEMATRON, test, text))
            rule_element.append(element)

    def _add_allowed_values_test(self, rule_element, context, entity_name,
                                 allowed_values):
        '''Adds a test to the rule element corresponding to values found in the Allowed Values
        column of a STIX profile document.'''
        entity_path = "%s/%s" % (context, entity_name)
        text = "The allowed values for %s are %s" % (entity_path,
                                                     allowed_values)

        if entity_name.startswith('@'):
            test = " or ".join("%s='%s'" % (entity_name, x)
                               for x in allowed_values)
        else:
            test = " or ".join(".='%s'" % (x) for x in allowed_values)

        element = etree.XML('<assert xmlns="%s" test="%s" role="error">%s '
                            '[<value-of select="saxon:line-number()"/>]</assert> '
                            % (self.NS_SCHEMATRON, test, text))
        rule_element.append(element)

    def _create_rule_element(self, context):
        '''Returns an etree._Element representation of a Schematron rule element.'''
        rule = etree.Element("{%s}rule" % self.NS_SCHEMATRON)
        rule.set('context', context)
        return rule

    def _add_rules(self, pattern_element, selectors, field_ns, tests):
        '''Adds all Schematron rules and tests to the overarching Schematron
        <pattern> element. Each rule and test corresponds to entries found
        in the STIX profile document.
        '''
        d_rules = {}  # context : rule_element
        for selector in selectors:
            for d_test in tests:
                field = d_test['field']
                occurrence = d_test['occurrence']
                allowed_values = d_test['allowed_values']
                allowed_xsi_types = d_test['xsi_types']

                if field.startswith("@"):
                    entity_name = field
                else:
                    entity_name = "%s:%s" % (field_ns, field)

                if occurrence == "required":
                    ctx = selector
                    rule = d_rules.setdefault(ctx, self._create_rule_element(ctx))
                    self._add_required_test(rule, entity_name, ctx)
                elif occurrence == "prohibited":
                    if entity_name.startswith("@"):
                        ctx = selector
                    else:
                        ctx = "%s/%s" % (selector, entity_name)

                    rule = d_rules.setdefault(ctx, self._create_rule_element(ctx))
                    self._add_prohibited_test(rule, entity_name, ctx)

                if allowed_values or allowed_xsi_types:
                    if entity_name.startswith('@'):
                        ctx = selector
                    else:
                        ctx = "%s/%s" % (selector, entity_name)

                    rule = d_rules.setdefault(ctx, self._create_rule_element(ctx))
                    if allowed_values:
                        self._add_allowed_values_test(rule,
                                                      selector,
                                                      entity_name,
                                                      allowed_values)
                    if allowed_xsi_types:
                        self._add_allowed_xsi_types_test(rule,
                                                         selector,
                                                         entity_name,
                                                         allowed_xsi_types)

        for rule in d_rules.itervalues():
            pattern_element.append(rule)

    def _build_schematron_xml(self, rules, nsmap, instance_map):
        '''Returns an etree._Element instance representation of the STIX profile'''
        root = etree.Element("{%s}schema" % self.NS_SCHEMATRON,
                             nsmap={None: self.NS_SCHEMATRON})
        pattern = self._add_element(root, "pattern", id="STIX_Schematron_Profile")
        self._add_root_test(pattern, nsmap)  # check the root element of the document

        for label, tests in rules.iteritems():
            d_instances = instance_map[label]
            selectors = d_instances['selectors']
            field_ns_alias = d_instances['ns_alias']
            self._add_rules(pattern, selectors, field_ns_alias, tests)

        self._map_ns(root, nsmap)  # add namespaces to the schematron document
        return root

    def _parse_namespace_worksheet(self, worksheet):
        '''Parses the Namespaces worksheet of the profile. Returns a dictionary representation:

        d = { <namespace> : <namespace alias> }

        By default, entries for http://stix.mitre.org/stix-1 and http://icl.com/saxon are added.

        '''
        nsmap = {self.NS_SAXON: 'saxon'}
        for i in xrange(1, worksheet.nrows):  # skip the first row
            if not any(self._get_cell_value(worksheet, i, x)
                       for x in xrange(0, worksheet.ncols)):  # empty row
                continue

            ns = self._get_cell_value(worksheet, i, 0)
            alias = self._get_cell_value(worksheet, i, 1)

            if not (ns or alias):
                raise Exception("Missing namespace or alias: unable to parse "
                                "Namespaces worksheet")

            nsmap[ns] = alias
        return nsmap

    def _parse_instance_mapping_worksheet(self, worksheet, nsmap):
        '''Parses the supplied Instance Mapping worksheet and returns a
        dictionary representation.

        d0  = { <STIX type label> : d1 }
        d1  = { 'selectors' : XPath selectors to instances of the XML datatype',
                'ns' : The namespace where the STIX type is defined,
                'ns_alias' : The namespace alias associated with the namespace }

        '''
        instance_map = {}
        for i in xrange(1, worksheet.nrows):
            if not any(self._get_cell_value(worksheet, i, x)
                       for x in xrange(0, worksheet.ncols)):  # empty row
                continue

            label = self._get_cell_value(worksheet, i, 0)
            selectors = [x.strip().replace('"', "'") for x in self._get_cell_value(worksheet, i,
                                                                 1).split(",")]

            for selector in selectors:
                if not selector:
                    raise Exception("Empty selector for '%s' in Instance Mapping "
                                    "worksheet. Look for "
                                    "extra commas in field." % label)

            ns = self._get_cell_value(worksheet, i, 2)
            ns_alias = nsmap[ns]

            if not (label or selectors or ns):
                raise Exception("Missing label, instance selector and/or "
                                "namespace for %s in Instance Mapping worksheet"
                                % label)

            instance_map[label] = {'selectors': selectors,
                                   'ns': ns,
                                   'ns_alias': ns_alias}
        return instance_map

    def _parse_profile(self, profile):
        '''Converts the supplied STIX profile into a Schematron representation.
         The Schematron schema is returned as a etree._Element instance.
        '''
        overview_ws = profile.sheet_by_name("Overview")
        namespace_ws = profile.sheet_by_name("Namespaces")
        instance_mapping_ws = profile.sheet_by_name("Instance Mapping")

        all_rules = defaultdict(list)
        for worksheet in profile.sheets():
            if worksheet.name not in ("Overview", "Namespaces", "Instance Mapping"):
                rules = self._build_rule_dict(worksheet)
                for context, d in rules.iteritems():
                    all_rules[context].extend(d)

        namespaces = self._parse_namespace_worksheet(namespace_ws)
        instance_mapping = self._parse_instance_mapping_worksheet(instance_mapping_ws,
                                                                  namespaces)
        schema = self._build_schematron_xml(all_rules, namespaces,
                                            instance_mapping)

        self._unload_workbook(profile)
        return schema

    def _map_ns(self, schematron, nsmap):
        '''Adds <ns> nodes to the supplied schematron document for each entry
        supplied by the nsmap.

        '''
        for ns, prefix in nsmap.iteritems():
            ns_element = etree.Element("{%s}ns" % self.NS_SCHEMATRON)
            ns_element.set("prefix", prefix)
            ns_element.set("uri", ns)
            schematron.insert(0, ns_element)

    def _add_element(self, node, name, text=None, **kwargs):
        '''Adds an etree._Element child to the supplied node. The child
        node is returned'''
        child = etree.SubElement(node, "{%s}%s" % (self.NS_SCHEMATRON, name))
        if text:
            child.text = text
        for k, v in kwargs.iteritems():
            child.set(k, v)
        return child

    def _unload_workbook(self, workbook):
        '''Unloads the xlrd workbook.'''
        for worksheet in workbook.sheets():
            workbook.unload_sheet(worksheet.name)

    def _get_cell_value(self, worksheet, row, col):
        '''Returns the worksheet cell value found at (row,col).'''
        if not worksheet:
            raise Exception("worksheet value was NoneType")
        value = str(worksheet.cell_value(row, col))
        return value

    def _convert_to_string(self, value):
        '''Returns the str(value) or an 8-bit string version of value
        encoded as UTF-8.'''
        if isinstance(value, unicode):
            return value.encode("UTF-8")
        else:
            return str(value)

    def _open_profile(self, filename):
        '''Returns xlrd.open_workbook(filename) or raises an Exception if the
        filename extension is not .xlsx or the open_workbook() call fails.

        '''
        if not filename.lower().endswith(".xlsx"):
            raise Exception("File must have .XLSX extension. Filename "
                            "provided: %s" % filename)
        try:
            return xlrd.open_workbook(filename)
        except:
            raise Exception("File does not seem to be valid XLSX.")

    def validate(self, instance_doc):
        '''Validates an XML instance document against a STIX profile.'''
        return super(STIXProfileValidator, self).validate(instance_doc,
                                                          report_line_numbers=False)

    def _build_error_dict(self, errors, instance_doc, report_line_numbers=False):
        '''Overrides SchematronValidator._build_error_dict(...).

        Returns a dictionary representation of the SVRL validation report:
        d0 = { <Schemtron error message> : d1 }

        d1 = { "locations" : A list of XPaths to context nodes,
               "line_numbers" : A list of line numbers where the error occurred,
               "test" : The Schematron evaluation expression used,
               "text" : The Schematron error message }

        '''
        d_errors = {}
        for error in errors:
            text = error.find("{%s}text" % self.NS_SVRL).text
            location = error.attrib.get('location')
            test = error.attrib.get('test')

            line_number = text.split(" ")[-1][1:-1]
            text = text[:text.rfind(' [')]

            if text in d_errors:
                d_errors[text]['locations'].append(location)
                d_errors[text]['line_numbers'].append(line_number)
            else:
                d_errors[text] = {'locations': [location],
                                  'test': test,
                                  'nsmap': error.nsmap,
                                  'text': text,
                                  'line_numbers': [line_number]}
        return d_errors

    def get_xslt(self):
        '''Overrides SchematronValidator.get_xslt()

        Returns an lxml.etree._ElementTree representation of the ISO Schematron
        skeleton generated XSLT translation of a STIX profile.

        The STIXProfileValidator uses the extension function saxon:line-number()
        for reporting line numbers. This function is stripped along with any
        references to the Saxon namespace from the exported XSLT. This is due
        to compatibility issues between Schematron/XSLT processing libraries.
        For example, SaxonPE/EE expects the Saxon namespace to be
        "http://saxon.sf.net/" while libxslt expects it to be
        "http://icl.com/saxon". The freely distributed SaxonHE library does not
        support Saxon extension functions at all.

        '''
        if not self.schematron:
            return None

        s = etree.tostring(self.schematron.validator_xslt)
        s = s.replace(' [<axsl:text/>'
                      '<axsl:value-of select="saxon:line-number()"/>'
                      '<axsl:text/>]', '')
        s = s.replace('xmlns:saxon="http://icl.com/saxon"', '')
        s = s.replace('<svrl:ns-prefix-in-attribute-values '
                      'uri="http://icl.com/saxon" prefix="saxon"/>', '')
        return etree.ElementTree(etree.fromstring(s))

    def get_schematron(self):
        '''Overrides SchematronValidator.get_schematron()

        Returns an lxml.etree._ElementTree representation of the ISO Schematron
        translation of a STIX profile.

        The STIXProfileValidator uses the extension function saxon:line-number()
        for reporting line numbers. This function is stripped along with any
        references to the Saxon namespace from the exported XSLT. This is due
        to compatibility issues between Schematron/XSLT processing libraries.
        For example, SaxonPE/EE expects the Saxon namespace to be
        "http://saxon.sf.net/" while libxslt expects it to be
        "http://icl.com/saxon". The freely distributed SaxonHE library does not
        support Saxon extension functions at all.

        '''
        if not self.schematron:
            return None

        s = etree.tostring(self.schematron.schematron)
        s = s.replace(' [<value-of select="saxon:line-number()"/>]', '')
        s = s.replace('<ns prefix="saxon" uri="http://icl.com/saxon"/>', '')
        return etree.ElementTree(etree.fromstring(s))
