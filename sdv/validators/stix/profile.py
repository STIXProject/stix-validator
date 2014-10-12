# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import xlrd
from StringIO import StringIO
from collections import defaultdict
from lxml import etree
import sdv.utils as utils
from sdv.validators.schematron import (SchematronValidator,
    SchematronValidationResults, SchematronError, SchematronReport, NS_SVRL,
    NS_SAXON, NS_SAXON_SF_NET, NS_SCHEMATRON)


class ProfileError(SchematronError):
    def __init__(self, doc, report, error):
        super(ProfileError, self).__init__(doc, report, error)
        self._line = self._parse_line(error)

    def _parse_line(self, error):
        message = error.find("{%s}text" % NS_SVRL)

        if message == None:
            return None

        line = message.text.split()[-1][1:-1]
        return line

    def _parse_message(self, error):
        message = error.find("{%s}text" % NS_SVRL)

        if message == None:
            return None

        text = message.text
        return text[:text.rfind(' [')]


class ProfileReport(SchematronReport):
    def __init__(self, doc, svrl_report):
        super(ProfileReport, self).__init__(doc, svrl_report)


    def _parse_errors(self, report):
        xpath = "//svrl:failed-assert | //svrl:successful-report"
        nsmap = {'svrl': NS_SVRL}
        errors = report.xpath(xpath, namespaces=nsmap)

        return [ProfileError(self._doc, report, x) for x in errors]


class ProfileValidationResults(SchematronValidationResults):
    def __init__(self, report):
        super(ProfileValidationResults, self).__init__(report)


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
                            % (NS_SCHEMATRON, test, text))
        rule_element.append(element)

    def _add_required_test(self, rule_element, entity_name, context):
        '''Adds a test to the rule element checking for the presence of a
        required STIX field.'''
        entity_path = "%s/%s" % (context, entity_name)
        text = "%s is required by this profile" % (entity_path)
        test = entity_name
        element = etree.XML('<assert xmlns="%s" test="%s" role="error">%s '
                            '[<value-of select="saxon:line-number()"/>]</assert> '
                            % (NS_SCHEMATRON, test, text))
        rule_element.append(element)

    def _add_prohibited_test(self, rule_element, entity_name, context):
        '''Adds a test to the rule element checking for the presence of a prohibited STIX field.'''
        entity_path = "%s/%s" % (context, entity_name) if entity_name.startswith("@") else context
        text = "%s is prohibited by this profile" % (entity_path)
        test_field = entity_name if entity_name.startswith("@") else "true()"
        element = etree.XML('<report xmlns="%s" test="%s" role="error">%s '
                            '[<value-of select="saxon:line-number()"/>]</report> '
                            % (NS_SCHEMATRON, test_field, text))
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
                                % (NS_SCHEMATRON, test, text))
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
                            % (NS_SCHEMATRON, test, text))
        rule_element.append(element)

    def _create_rule_element(self, context):
        '''Returns an etree._Element representation of a Schematron rule element.'''
        rule = etree.Element("{%s}rule" % NS_SCHEMATRON)
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
        root = etree.Element("{%s}schema" % NS_SCHEMATRON,
                             nsmap={None: NS_SCHEMATRON})
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
        nsmap = {NS_SAXON: 'saxon'}
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
            ns_element = etree.Element("{%s}ns" % NS_SCHEMATRON)
            ns_element.set("prefix", prefix)
            ns_element.set("uri", ns)
            schematron.insert(0, ns_element)

    def _add_element(self, node, name, text=None, **kwargs):
        '''Adds an etree._Element child to the supplied node. The child
        node is returned'''
        child = etree.SubElement(node, "{%s}%s" % (NS_SCHEMATRON, name))
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
        return etree.parse(StringIO(s))

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
        return etree.parse(StringIO(s))


    def validate(self, doc):
        '''Validates an XML instance document against a STIX profile.'''

        root = utils.get_etree_root(doc)
        is_valid = self.schematron.validate(root)
        svrl_report = self.schematron.validation_report
        report = ProfileReport(root, svrl_report)

        results = ProfileValidationResults(report)
        results.is_valid = is_valid

        return results