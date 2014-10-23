# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import xlrd
import collections
import functools
from StringIO import StringIO
from lxml import etree

import sdv.utils as utils
import sdv.errors as errors
from sdv.validators import schematron

# Rule worksheet columns
COL_FIELD_NAME     = 0
COL_OCCURRENCE     = 1
COL_XSI_TYPES      = 3
COL_ALLOWED_VALUES = 4

# Instance mapping worksheet columns
COL_LABEL = 0
COL_SELECTORS = 1
COL_TYPE_NAMESPACE = 2

# Namespace worksheet columns
COL_NAMESPACE = 0
COL_ALIAS = 1

# Occurrence values
OCCURRENCE_PROHIBITED = 'prohibited'
OCCURRENCE_REQUIRED   = 'required'
ALLOWED_OCCURRENCES = (OCCURRENCE_PROHIBITED, OCCURRENCE_REQUIRED)


def _is_attr(fieldname):
    return fieldname.startswith("@")


class Profile(collections.MutableSequence):
    def __init__(self, namespaces):
        self.id_ = "STIX_Schematron_Profile"
        self._rules = []
        self._namespaces = namespaces

    def insert(self, idx, value):
        if not value:
            return
        self._rules.insert(idx, value)

    def __getitem__(self, key):
        return self._rules.__getitem__(key)

    def __setitem__(self, key, value):
        self._rules.__setitem__(key, value)

    def __delitem__(self, key):
        self._rules.__delitem__(key)

    def __len__(self):
        return len(self._rules)

    def __nonzero__(self):
        return bool(self._rules)


    def _collect_rules(self):
        collected = collections.defaultdict(list)

        def _build_ctx_path(test):
            if test.is_attr:
                return test.context
            return "{0}/{1}".format(test.context, test.field)

        for test in self:
            if isinstance(test, (AllowedImplsRule, AllowedValuesRule)):
                rule_ctx = _build_ctx_path(test)
            else:
                rule_ctx = test.context

            collected[rule_ctx].append(test)

        return collected

    def _create_rule(self, ctx):
        return etree.XML(
            '<rule xmlns="%s" context="%s"/>' % (schematron.NS_SCHEMATRON, ctx)
        )

    @property
    def rules(self):
        rules = []
        collected = self._collect_rules()

        for ctx, tests in collected.iteritems():
            rule = self._create_rule(ctx)
            rule.extend([test.as_etree() for test in tests])
            rules.append(rule)

        return rules

    def _get_root_rule(self):
        ns_stix = "http://stix.mitre.org/stix-1"
        text = "The root element must be a STIX_Package instance"
        test = "%s:STIX_Package" % self._namespaces.get(ns_stix, 'stix')

        rule = self._create_rule("/")

        assertion = etree.XML(
            '<assert xmlns="%s" test="%s" role="error">%s '
            '[<value-of select="saxon:line-number()"/>]</assert> ' %
            (schematron.NS_SCHEMATRON, test, text)
        )

        rule.append(assertion)
        return rule

    def _get_schema_node(self):
        return etree.Element(
            "{%s}schema" % schematron.NS_SCHEMATRON,
            nsmap={None: schematron.NS_SCHEMATRON}
        )


    def _get_pattern_node(self):
        return etree.XML(
            "<pattern xmlns='%s' id='%s'/>" % (schematron.NS_SCHEMATRON, self.id_)
        )

    def _get_namespaces(self):
        namespaces = []

        for ns, prefix in self._namespaces.iteritems():
            namespace = etree.Element("{%s}ns" % schematron.NS_SCHEMATRON)
            namespace.set("prefix", prefix)
            namespace.set("uri", ns)
            namespaces.append(namespace)

        return namespaces

    def as_etree(self):
        pattern = self._get_pattern_node()
        pattern.append(self._get_root_rule())
        pattern.extend(self.rules)

        schema = self._get_schema_node()
        schema.extend(self._get_namespaces())
        schema.append(pattern)

        return schema


class _BaseProfileRule(object):
    _TYPE_REPORT  = "report"
    _TYPE_ASSERT  = "assert"

    def __init__(self, context, field):
        self._type = None
        self._role = "error"
        self.context = context
        self.field = field
        self._validate()

    def _validate(self):
        pass

    @property
    def role(self):
        return self._role

    @property
    def type_(self):
        return self._type

    @property
    def is_attr(self):
        return self.field.startswith("@")


    @property
    def message(self):
        raise NotImplementedError()


    @property
    def test(self):
        raise NotImplementedError()


    def as_etree(self):
        line_number = '[<value-of select="saxon:line-number()"/>]'

        args = (
            self.type_,                  # assert or report
            schematron.NS_SCHEMATRON,    # schematron namespace
            self.test,                   # test selector
            self.role,                  # "error"
            self.message,                # error message
            line_number                  # line number function
        )

        rule = etree.XML(
            '<{0} xmlns="{1}" test="{2}" role="{3}">{4} {5}</{0}>'.format(*args)
        )

        return rule


class RequiredRule(_BaseProfileRule):
    def __init__(self, context, field):
        super(RequiredRule, self).__init__(context, field)
        self._type = self._TYPE_ASSERT

    @_BaseProfileRule.test.getter
    def test(self):
        return self.field

    @_BaseProfileRule.test.getter
    def message(self):
        return "{0}/{1} is required by this profile.".format(
            self.context, self.field
        )


class ProhibitedRule(_BaseProfileRule):
    def __init__(self, context, field):
        super(ProhibitedRule, self).__init__(context, field)
        self._type = self._TYPE_REPORT

    @_BaseProfileRule.test.getter
    def test(self):
        return self.field

    @_BaseProfileRule.message.getter
    def message(self):
        return "{0}/{1} is prohibited by this profile.".format(
            self.context, self.field
        )


class AllowedValuesRule(_BaseProfileRule):
    def __init__(self, context, field, values=None):
        super(AllowedValuesRule, self).__init__(context, field)
        self._type = self._TYPE_ASSERT
        self.values = values

    @property
    def values(self):
        return self._values

    @values.setter
    def values(self, value):
        if not value:
            self._values = []
        elif isinstance(value, basestring):
            self._values = [x.strip() for x in value.split(',')]
        elif hasattr(value, "__getitem__"):
            self._values = value
        else:
            self._values = [value]

    @_BaseProfileRule.message.getter
    def message(self):
       return "The allowed values for {0}/{1} are {2}".format(
           self.context, self.field, self.values
       )

    @_BaseProfileRule.test.getter
    def test(self):
        name = self.field
        allowed = self.values

        if name.startswith("@"):
            test = " or ".join("%s='%s'" % (name, x) for x in allowed)
        else:
            test = " or ".join(".='%s'" % (x) for x in allowed)

        return test


class AllowedImplsRule(_BaseProfileRule):
    def __init__(self, context, field, impls=None):
        super(AllowedImplsRule, self).__init__(context, field)
        self._type = self._TYPE_ASSERT
        self.impls = impls

    def _validate(self):
        if self.is_attr:
            raise errors.ProfileParseError(
                "Allowed implementation rules cannot be applied to attributes"
            )

    @property
    def impls(self):
        return self._impls

    @impls.setter
    def impls(self, value):
        if not value:
            self._impls = []
        elif isinstance(value, basestring):
            self._impls = [x.strip() for x in value.split(',')]
        elif hasattr(value, "__getitem__"):
            self._impls = value
        else:
            self._impls = [value]

    @_BaseProfileRule.message.getter
    def message(self):
       return "The allowed implementations for {0}/{1} are {2}".format(
           self.context, self.field, self.impls
       )

    @_BaseProfileRule.test.getter
    def test(self):
       return " or ".join("@xsi:type='%s'" % (x,) for x in self.impls)


class ProfileError(schematron.SchematronError):
    """Represents STIX profile validation error."""

    def __init__(self, doc, error):
        super(ProfileError, self).__init__(doc, error)
        self._line = self._parse_line(error)


    def _parse_line(self, error):
        """Errors are reported as ``<error msg> [line number]``.

        This method parses the line number out of th error message.

        Returns:
            A string line number for the `error`.

        """
        text = super(ProfileError, self)._parse_message(error)

        if not text:
            return None

        # Split the string on whitespace.
        # Get the last item.
        # Strip the leading '[' and trailing ']'.
        line = text.split()[-1][1:-1]

        return line


    def _parse_message(self, error):
        text = super(ProfileError, self)._parse_message(error)

        if not text:
            return None

        return text[:text.rfind(' [')]


class ProfileValidationResults(schematron.SchematronValidationResults):
    """Represents STIX profile validation results. This is returned from
    the :meth:`STIXProfileValidator.valdate` method.

    Args:
        is_vaild: ``True`` if the document was valid and ``False`` otherwise.
        doc: The document that was validated. This is an instance of
            lxml._Element.
        svrl_report: The SVRL report. This is an instance of
            ``lxml.isoschematron.Schematron.validation_report``

    Attributes:
        is_valid: ``True`` if the validation attempt was successful. ``False``
            if the associated instance document was invalid.
        errors: A list of :class:`ProfileError` instances representing
            errors found in the `svrl_report`.

    """
    def __init__(self, is_valid, doc=None, svrl_report=None):
        super(ProfileValidationResults, self).__init__(
            is_valid=is_valid, doc=doc, svrl_report=svrl_report
        )

    def _parse_errors(self, svrl_report):
        if not svrl_report:
            return None

        xpath = "//svrl:failed-assert | //svrl:successful-report"
        nsmap = {'svrl': schematron.NS_SVRL}
        errors = svrl_report.xpath(xpath, namespaces=nsmap)

        return [ProfileError(self._doc, x) for x in errors]


class STIXProfileValidator(schematron.SchematronValidator):
    """Performs STIX Profile validation.

    Args:
        profile_fn: The filename of a .XLSX STIX Profile document.

    """
    def __init__(self, profile_fn):
        workbook = self._open_workbook(profile_fn)
        profile = self._parse_profile(workbook)
        self._unload_workbook(workbook)

        super(STIXProfileValidator, self).__init__(schematron=profile)


    def _build_rules(self, label, instance_map, field, occurrence, types, values):
        selectors = instance_map[label]['selectors']
        ns_alias = instance_map[label]['ns_alias']

        rules = []
        for context in selectors:
            if not _is_attr(field):
                fieldname = "%s:%s" % (ns_alias, field)
            else:
                fieldname = field

            if occurrence == OCCURRENCE_REQUIRED:
                rule = RequiredRule(context, fieldname)
                rules.append(rule)
            elif occurrence == OCCURRENCE_PROHIBITED:
                rule = ProhibitedRule(context, fieldname)
                rules.append(rule)
                continue  # Cannot set prohibited values or impls
            else:
                continue  # Only build rules for 'prohibited' and 'required'

            if types:
                rule = AllowedImplsRule(context, fieldname, types)
                rules.append(rule)

            if values:
                rule = AllowedValuesRule(context, fieldname, values)
                rules.append(rule)

        return rules

    def _parse_rules_worksheet(self, worksheet, instance_map):
        """Builds a dictionary representation of the rules defined by a STIX
        profile document.

        """
        all_rules = []
        value = functools.partial(self._get_value, worksheet)  # Tidy up!

        def _is_empty_row(worksheet, row):
            return not any(value(row, x) for x in xrange(worksheet.ncols))

        for i in xrange(1, worksheet.nrows):
            if _is_empty_row(worksheet, i):
                continue

            if not value(i, COL_OCCURRENCE):
                ctx_label = value(i, COL_FIELD_NAME)
                continue

            field = value(i, COL_FIELD_NAME)
            occurrence = value(i, COL_OCCURRENCE).lower()
            types = value(i, COL_XSI_TYPES)
            values = value(i, COL_ALLOWED_VALUES)

            if occurrence not in ALLOWED_OCCURRENCES:
                continue

            rules = self._build_rules(
                ctx_label, instance_map, field, occurrence, types, values
            )

            all_rules.extend(rules)

        return all_rules



    def _parse_namespace_worksheet(self, worksheet):
        '''Parses the Namespaces worksheet of the profile. Returns a dictionary
        representation:

        d = { <namespace> : <namespace alias> }

        By default, entries for http://stix.mitre.org/stix-1 and
        http://icl.com/saxon are added.

        '''
        value = functools.partial(self._get_value, worksheet)
        nsmap = {schematron.NS_SAXON: 'saxon'}

        def _is_empty_row(worksheet, row):
            return not any(value(row, x) for x in xrange(worksheet.ncols))

        for i in xrange(1, worksheet.nrows):  # skip the first row
            if _is_empty_row(worksheet, i):
                continue

            ns = value(i, COL_NAMESPACE)
            alias = value(i, COL_ALIAS)

            if not all((ns, alias)):
                raise errors.ProfileParseError(
                    "Missing namespace or alias: unable to parse "
                    "Namespaces worksheet"
                )

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
        value = functools.partial(self._get_value, worksheet)
        instance_map = {}

        def _is_empty_row(worksheet, row):
            return not any(value(row, x) for x in xrange(worksheet.ncols))

        for i in xrange(1, worksheet.nrows):
            if _is_empty_row(worksheet, i):
                continue

            label = value(i, COL_LABEL)
            namespace = value(i, COL_TYPE_NAMESPACE)
            selectors = value(i, COL_SELECTORS)
            selectors = [x.strip().replace('"', "'") for x in selectors.split(",")]

            if not all(selectors):
                raise errors.ProfileParseError(
                    "Empty selector for '%s' in Instance Mapping "
                    "worksheet. Look for extra commas in field." % label
                )

            if not all((label, selectors, namespace)):
                raise errors.ProfileParseError(
                    "Missing label, instance selector and/or "
                    "namespace for %s in Instance Mapping worksheet" % label
                )

            instance_map[label] = {
                'selectors': selectors,
                'ns': namespace,
                'ns_alias': nsmap[namespace]
            }

        return instance_map


    def _parse_rules(self, workbook, instance_map):
        skip = ("Overview", "Namespaces", "Instance Mapping")

        all_rules = []
        for worksheet in workbook.sheets():
            if worksheet.name in skip:
                continue

            rules = self._parse_rules_worksheet(worksheet, instance_map)
            all_rules.extend(rules)

        return all_rules


    def _parse_profile(self, workbook):
        """Converts the supplied STIX profile into a Schematron representation.
         The Schematron schema is returned as a etree._Element instance.

        """
        ws = workbook.sheet_by_name
        namespaces = self._parse_namespace_worksheet(ws("Namespaces"))
        instance_mapping = self._parse_instance_mapping_worksheet(
                ws("Instance Mapping"),  namespaces
        )

        profile = Profile(namespaces)
        rules = self._parse_rules(workbook, instance_mapping)
        profile.extend(rules)
        return profile.as_etree()


    def _unload_workbook(self, workbook):
        '''Unloads the xlrd workbook.'''
        for worksheet in workbook.sheets():
            workbook.unload_sheet(worksheet.name)


    def _get_value(self, worksheet, row, col):
        '''Returns the worksheet cell value found at (row,col).'''
        if not worksheet:
            raise errors.ProfileParseError("worksheet value was NoneType")

        return str(worksheet.cell_value(row, col))


    def _open_workbook(self, filename):
        """Returns xlrd.open_workbook(filename) or raises an Exception if the
        filename extension is not .xlsx or the open_workbook() call fails.

        """
        if not filename.lower().endswith(".xlsx"):
            raise errors.ProfileParseError(
                "File must have .XLSX extension. Filename provided: %s" %
                filename
            )

        try:
            return xlrd.open_workbook(filename)
        except:
            raise errors.ProfileParseError(
                "File does not seem to be valid XLSX."
            )

    @schematron.SchematronValidator.xslt.getter
    def xslt(self):
        """Returns an lxml.etree._ElementTree representation of the ISO
        Schematron skeleton generated XSLT translation of a STIX profile.

        The STIXProfileValidator uses the extension function saxon:line-number()
        for reporting line numbers. This function is stripped along with any
        references to the Saxon namespace from the exported XSLT. This is due
        to compatibility issues between Schematron/XSLT processing libraries.
        For example, SaxonPE/EE expects the Saxon namespace to be
        "http://saxon.sf.net/" while libxslt expects it to be
        "http://icl.com/saxon". The freely distributed SaxonHE library does not
        support Saxon extension functions at all.

        """
        if not self._schematron:
            return None

        s = etree.tostring(self._schematron.validator_xslt)
        s = s.replace(
            ' [<axsl:text/>'
            '<axsl:value-of select="saxon:line-number()"/>'
            '<axsl:text/>]',
            ''
        )
        s = s.replace('xmlns:saxon="http://icl.com/saxon"', '')
        s = s.replace(
            '<svrl:ns-prefix-in-attribute-values '
            'uri="http://icl.com/saxon" prefix="saxon"/>',
            ''
        )

        return etree.parse(StringIO(s))

    @schematron.SchematronValidator.schematron.getter
    def schematron(self):
        """Returns an lxml.etree._ElementTree representation of the
        ISO Schematron translation of a STIX profile.

        The STIXProfileValidator uses the extension function saxon:line-number()
        for reporting line numbers. This function is stripped along with any
        references to the Saxon namespace from the exported XSLT. This is due
        to compatibility issues between Schematron/XSLT processing libraries.
        For example, SaxonPE/EE expects the Saxon namespace to be
        "http://saxon.sf.net/" while libxslt expects it to be
        "http://icl.com/saxon". The freely distributed SaxonHE library does not
        support Saxon extension functions at all.

        """
        s = etree.tostring(self._schematron.schematron)
        s = s.replace(' [<value-of select="saxon:line-number()"/>]', '')
        s = s.replace('<ns prefix="saxon" uri="http://icl.com/saxon"/>', '')

        return etree.parse(StringIO(s))


    def validate(self, doc):
        """Validates an XML instance document against a STIX profile.

        Args:
            doc: A STIX XML instance document.

        Returns:
            An instance of :class:`ProfileValidationResults`.

        """
        root = utils.get_etree_root(doc)
        is_valid = self._schematron.validate(root)
        svrl_report = self._schematron.validation_report

        return ProfileValidationResults(is_valid, root, svrl_report)
