# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import os
import itertools
import collections
import contextlib
import functools
import StringIO

# external
import xlrd
from lxml import etree

# internal
from sdv import errors, utils, xmlconst

# relative
from . import common
from .. import schematron


# Rule worksheet columns
COL_FIELD_NAME     = 0
COL_OCCURRENCE     = 1
COL_XSI_TYPES      = 3
COL_ALLOWED_VALUES = 4

# Instance Mapping worksheet columns
COL_LABEL          = 0
COL_SELECTORS      = 1
COL_TYPE_NAMESPACE = 2

# Namespace worksheet columns
COL_NAMESPACE      = 0
COL_ALIAS          = 1

# Occurrence values
OCCURRENCE_PROHIBITED       = ('prohibited', 'must not')
OCCURRENCE_REQUIRED         = ('required', 'must')
OCCURRENCE_OPTIONAL         = ('optional', 'may')
OCCURRENCE_SUGGESTED        = ('suggested', 'should')
OCCURRENCE_DISCOURAGED      = ('should not',)
ALL_OPTIONAL_OCCURRENCES    = tuple(
    itertools.chain(
        OCCURRENCE_OPTIONAL,
        OCCURRENCE_SUGGESTED,
        OCCURRENCE_DISCOURAGED
    )
)
ALLOWED_OCCURRENCES         = tuple(
    itertools.chain(
        OCCURRENCE_OPTIONAL,
        OCCURRENCE_PROHIBITED,
        OCCURRENCE_DISCOURAGED,
        OCCURRENCE_REQUIRED,
        OCCURRENCE_SUGGESTED
    )
)

# Used by profile schematron for reporting error line numbers.
SAXON_LINENO = '[<value-of select="saxon:line-number()"/>]'


class InstanceMapping(object):
    """Contains information about an entry in the Instance Mapping worksheet
    of a Profile.

    Args:
        nsmap: A dictionary representation of the Namespaces worksheet.

    Attributes:
        selectors: A list of instance selectors for an Instance Mapping entry.
        namespace: The type namespace for an Instance Mapping entry.
        ns_alias: The namespace alias for the `namespace` to be used in the
            output profile schematron.
    """
    def __init__(self, nsmap):
        self._nsmap = nsmap
        self._ns_alias  = None
        self.label = None
        self.selectors = None
        self.namespace = None

    @property
    def selectors(self):
        return self._selectors

    @selectors.setter
    def selectors(self, value):
        """Parses the cell value found in the Excel STIX profile for Instance
        Mapping selectors.

        Args:
            value: An single selector, list of selectors, or a
            comma-delimited string of selectors.

        """
        if not value:
            self._selectors = []
        elif isinstance(value, basestring):
            self._selectors = [
                x.strip().replace('"', "'") for x in value.split(",")
            ]
        elif hasattr(value, "__getitem__"):
            self._selectors = [str(x) for x in value]
        else:
            self._selectors = [value]

    @property
    def namespace(self):
        return self._namespace

    @namespace.setter
    def namespace(self, value):
        """Sets the namespace and ns_alias properties.

        Raises:
            .ProfileParseError: if `value` is not found in the internal
                namespace dictionary.

        """
        if not value:
            self._namespace = None
            self._ns_alias = None
        else:
            if value not in self._nsmap:
                raise errors.ProfileParseError(
                    "Unable to map namespace '%s' to namespace alias" % value
                )

            self._namespace = value
            self._ns_alias = self._nsmap[value]

    @property
    def ns_alias(self):
        return self._ns_alias

    def validate(self):
        """Checks that this is a valid InstanceMapping instance.

        Raises:
            errors.ProfileParseError: If ``namespace`` is ``None`` or
                any of the selector values are empty.

        """
        if not self.label:
            raise errors.ProfileParseError(
                "Missing type label in Instance Mapping"
            )

        if not self.namespace:
            raise errors.ProfileParseError(
                "Missing namespace for '%s' in Instance Mapping "
                "worksheet" % self.label
            )

        if not (self.selectors and all(self.selectors)):
            raise errors.ProfileParseError(
                "Empty selector for '%s' in Instance Mapping "
                "worksheet. Look for extra commas in field." % self.label
            )


class Profile(collections.MutableSequence):
    def __init__(self, namespaces):
        self.id = "STIX_Schematron_Profile"
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
        """Builds and returns a dictionary of ``BaseProfileRule``
        implementations from the internal storage. The key is the Rule context
        (e.g., "/", "stix:Indicator", "stix:STIX_Header/stix:Package_Intent").

        Determining the context of a profile rule is done by examining the
        following properties of the rule:

        * If the rule is a Prohibits or Requires occurrence check, the
            context is pulled directly from the _BaseProfileRule instance's
            ``context`` property. This value is derived from the context
            label associated with the rule entry in the profile worksheet.
        * If the rule checks for allowed values or implementations of an
            element the context will be a selector pointing directly to the
            element. This is done to cut down on validation noise (otherwise a
            missing element would raise errors for a required element being
            missing AND the element not containing an allowed value because it
            wasn't found at all).
        * If the rule checks for allowed values of an attribute, the rule
            context will pulled directly from the _BaseProfileRule instance's
            ``context`` property. This should probably follow the rules
            described above, but doesn't for no good reason.

        Returns:
            A dictionary of lists of rules associated by ``<rule>`` context.

        """
        collected = collections.defaultdict(list)

        for test in self:
            collected[test.context_selector].append(test)

        return collected

    def _create_rule(self, ctx):
        return etree.XML(
            '<rule xmlns="%s" context="%s"/>' % (xmlconst.NS_SCHEMATRON, ctx)
        )

    @property
    def rules(self):
        """Builds and returns a dictionary of ``BaseProfileRule``
        implementations. The key is the Rule context.

        """
        rules = []
        collected = self._collect_rules()

        for ctx, tests in collected.iteritems():
            rule = self._create_rule(ctx)
            rule.extend([test.as_etree() for test in tests])
            rules.append(self._pattern(rule))

        return rules

    def _get_root_rule(self):
        """Returns a Schematron rule which checks that the root element of
        the XML instance document is a ``STIX_Package``

        """

        ns_stix = "http://stix.mitre.org/stix-1"
        text = "The root element must be a STIX_Package instance"
        test = "%s:STIX_Package" % self._namespaces.get(ns_stix, 'stix')

        rule = self._create_rule("/")
        assertion = etree.XML(
            '<assert xmlns="%s" test="%s" role="error">%s %s</assert> ' %
            (xmlconst.NS_SCHEMATRON, test, text, SAXON_LINENO)
        )

        rule.append(assertion)
        pattern = self._pattern(rule)
        return pattern

    def _get_schema_node(self):
        return etree.Element(
            "{%s}schema" % xmlconst.NS_SCHEMATRON,
            nsmap={None: xmlconst.NS_SCHEMATRON}
        )

    def _pattern(self, rule):
        ns = xmlconst.NS_SCHEMATRON
        pattern = etree.XML("<pattern xmlns='{0}'/>".format(ns))
        pattern.append(rule)
        return pattern

    def _get_namespaces(self):
        """Returns a list of etree Elements that represent Schematron
        ``<ns prefix='foo' uri='bar'>`` elements.

        """
        namespaces = []

        for ns, prefix in self._namespaces.iteritems():
            namespace = etree.Element("{%s}ns" % xmlconst.NS_SCHEMATRON)
            namespace.set("prefix", prefix)
            namespace.set("uri", ns)
            namespaces.append(namespace)

        return namespaces

    def as_etree(self):
        """Returns an etree Schematron document for this ``Profile``."""
        patterns = []
        patterns.append(self._get_root_rule())
        patterns.extend(self.rules)

        schema = self._get_schema_node()
        schema.extend(self._get_namespaces())
        schema.extend(patterns)

        return schema


class _BaseProfileRule(object):
    """Base class for profile rules.

    Attributes:
        context: The context selector for this rule. This is determined by
            linking the rule context label to a selector.
        field: The name of the element or attribute for which this rule
            applies.

    Args:
        context: The context selector for this rule. This is determined by
            linking the rule context label to a selector.
        field: Tne name of the element or attribute for which this rule
            applies.

    """
    _TYPE_REPORT  = "report"
    _TYPE_ASSERT  = "assert"

    def __init__(self, context, field):
        self._type = None
        self._role = "error"
        self._context = context
        self.field = field
        self._validate()

    def _validate(self):
        """Perform validation/sanity checks on the input values."""
        pass

    @property
    def role(self):
        """Returns the Schematron assertion role for this rule."""
        return self._role

    @property
    def type(self):
        """The type of Schematron test: ``report`` or ``assert``."""
        return self._type

    @property
    def is_attr(self):
        """Returns ``True`` if this rule is defined for an attribute field."""
        return self.field.startswith("@")

    @property
    def message(self):
        """Returns the error message to be displayed if this rule does not
        evaluate successfully.

        """
        raise NotImplementedError()

    @property
    def test(self):
        """The xpath test to evaluate against a node."""
        raise NotImplementedError()

    @property
    def context_selector(self):
        """Returns the schematron rule context selector to be used for this
        schematron assert/report 'rule'.

        """
        raise NotImplementedError()

    @property
    def path(self):
        """Returns the fully qualified ``context/field`` path to the XML node
        for which this assert/report applies.

        """
        return "{0}/{1}".format(self._context, self.field)

    def as_etree(self):
        """Returns a Schematron ``<assert>`` or ``<report>`` for this
        profile rule.

        """
        args = (
            self.type,                   # 'assert' or 'report'
            xmlconst.NS_SCHEMATRON,      # schematron namespace
            self.test,                   # test selector
            self.role,                   # "error"
            self.message,                # error message
            SAXON_LINENO                 # line number function
        )

        xml = '<{0} xmlns="{1}" test="{2}" role="{3}">{4} {5}</{0}>'
        rule = etree.XML(xml.format(*args))

        return rule


class RequiredRule(_BaseProfileRule):
    """Represents a profile rule which requires the presence of an element
    or attribute.

    This serializes to a Schematron ``<assert>`` directive as
    it will raise an error if the field is **not** found in the instance
    document.

    """
    def __init__(self, context, field):
        super(RequiredRule, self).__init__(context, field)
        self._type = self._TYPE_ASSERT

    @_BaseProfileRule.test.getter
    def test(self):
        return self.field

    @_BaseProfileRule.context_selector.getter
    def context_selector(self):
        return self._context

    @_BaseProfileRule.test.getter
    def message(self):
        return "{0} is required by this profile.".format(self.path)


class ProhibitedRule(_BaseProfileRule):
    """Represents a profile rule which prohibits the use of a particular
    attribute or field.

    This serializes to a Schematron ``<report>`` directive
    as it will raise an error if the field **is found** in the instance
    document.

    """
    def __init__(self, context, field):
        super(ProhibitedRule, self).__init__(context, field)
        self._type = self._TYPE_REPORT

    @_BaseProfileRule.test.getter
    def test(self):
        return self.field

    @_BaseProfileRule.context_selector.getter
    def context_selector(self):
        return self._context

    @_BaseProfileRule.message.getter
    def message(self):
        return "{0} is prohibited by this profile.".format(self.path)


class AllowedValuesRule(_BaseProfileRule):
    """Represents a profile rule which requires that a field value be one
    of a defined set of allowed values.

    This serializes to a schematron ``<assert>`` directive.

    """
    def __init__(self, context, field, required=True, values=None):
        super(AllowedValuesRule, self).__init__(context, field)
        self._type = self._TYPE_ASSERT
        self.is_required = required
        self.values = values

    @property
    def values(self):
        return self._values

    @values.setter
    def values(self, value):
        """Parses the cell value found in the Excel STIX profile for allowable
        values.

        Args:
            value: An allowed value, list of allowed values, or a
            comma-delimited string of allowed values.

        """
        if not value:
            self._values = []
        elif isinstance(value, basestring):
            self._values = [x.strip() for x in value.split(',')]
        elif hasattr(value, "__getitem__"):
            self._values = [str(x) for x in value]
        else:
            self._values = [value]

    @_BaseProfileRule.context_selector.getter
    def context_selector(self):
        if self.is_attr and self.is_required:
            return self._context
        else:
            return self.path

    @_BaseProfileRule.message.getter
    def message(self):
        return "The allowed values for {0} are {1}".format(
            self.path, self.values
        )

    @_BaseProfileRule.test.getter
    def test(self):
        """Returns a test to check that a field is equal to one of the
        allowable values.

        This expects the ``<assert>`` directive to be places within a rule
        where the selector is the field name if this rule applies to an
        element name.

        If the resulting ``<assert>`` applies to an attribute, this assumes
        that the ``<rule>`` context will point to a parent element.

        """
        name = self.field
        allowed = self.values

        if self.is_attr and self.is_required:
            test = " or ".join("%s='%s'" % (name, x) for x in allowed)
        else:
            test = " or ".join(".='%s'" % (x) for x in allowed)

        return test


class AllowedImplsRule(_BaseProfileRule):
    def __init__(self, context, field, required=True, impls=None):
        super(AllowedImplsRule, self).__init__(context, field)
        self._type = self._TYPE_ASSERT
        self.is_required = required
        self.impls = impls

    def _validate(self):
        if not self.is_attr:
            return

        raise errors.ProfileParseError(
            "Implementation rules cannot be applied to attribute fields: "
            "{0}".format(self.path)
        )

    @property
    def impls(self):
        return self._impls

    @impls.setter
    def impls(self, value):
        """Parses the cell value found in the Excel STIX profile for allowable
        implementations.

        Args:
            value: An allowed implementation value, list of allowed
            implementations, or a comma-delimited string of allowed
            implementations.

        """
        if not value:
            self._impls = []
        elif isinstance(value, basestring):
            self._impls = [x.strip() for x in value.split(',')]
        elif hasattr(value, "__getitem__"):
            self._impls = [str(x) for x in value]
        else:
            self._impls = [value]

    @_BaseProfileRule.context_selector.getter
    def context_selector(self):
        return self.path

    @_BaseProfileRule.message.getter
    def message(self):
        msg = "The allowed implementations for {0} are {1}"
        msg = msg.format(self.path, self.impls)
        return msg

    @_BaseProfileRule.test.getter
    def test(self):
        """Returns a test to check that a field implementation is set to
        one of the allowable values.

        This expects the ``<assert>`` directive to be places within a rule
        where the selector is the field name if this rule applies to an
        element name.

        """
        return " or ".join("@xsi:type='%s'" % (x,) for x in self.impls)


class ProfileError(schematron.SchematronError):
    """Represents STIX profile validation error.

    Args:
        doc: The instance document which was validated and produced this error.
        error: The ``svrl:failed-assert`` or ``svrl:successful-report``
            ``etree._Element`` instance.

    Attributes:
        message: The STIX Profile validation error message.

    """

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

    def __unicode__(self):
        return super(ProfileError, self).__unicode__()

    def __str__(self):
        return super(ProfileError, self).__str__()

    def _parse_message(self, error):
        """Parses the message component from the SVRL report error message.

        Profile error messages are formatted as follows:
        ``<Error message text> [<line number>]``.

        This method returns everything left of the line number marker `` [``.

        """
        text = super(ProfileError, self)._parse_message(error)

        if not text:
            return None

        return text[:text.rfind(' [')]


class ProfileValidationResults(schematron.SchematronValidationResults):
    """Represents STIX profile validation results. This is returned from
    the :meth:`STIXProfileValidator.validate` method.

    Args:
        is_vaild: ``True`` if the document was valid and ``False`` otherwise.
        doc: The document that was validated. This is an instance of
            lxml._Element.
        svrl_report: The SVRL report. This is an instance of
            ``lxml.isoschematron.Schematron.validation_report``

    Attributes:
        errors: A list of :class:`ProfileError` instances representing
            errors found in the `svrl_report`.

    """
    def __init__(self, is_valid, doc=None, svrl_report=None):
        super(ProfileValidationResults, self).__init__(
            is_valid=is_valid,
            doc=doc,
            svrl_report=svrl_report
        )

    def _parse_errors(self, svrl_report):
        if not svrl_report:
            return None

        xpath = "//svrl:failed-assert | //svrl:successful-report"
        nsmap = {'svrl': xmlconst.NS_SVRL}
        errors = svrl_report.xpath(xpath, namespaces=nsmap)

        return [ProfileError(self._doc, x) for x in errors]


class STIXProfileValidator(schematron.SchematronValidator):
    """Performs STIX Profile validation.

    Args:
        profile_fn: The filename of a ``.xlsx`` STIX Profile document.

    """
    def __init__(self, profile_fn):
        self._schematron = None  # silence pylint

        with self._parse_profile(profile_fn) as profile:
            super(STIXProfileValidator, self).__init__(schematron=profile)

    def _build_rules(self, info, field, occurrence, types, values):
        """Builds a ``_BaseProfileRule`` implementation list for the rule
        parameters.

        Each rule can be broken up into the following components:

        * Context Label: Any label that can be mapped to one or more instance
            document selectors. For example: 'indicator:Indicator' which could
            be mapped ('//indicator:Indicator', '//stixCommon:Indicator',
            '//stix:Indicator'). The context label does not need to refer to
            a schema data type, but often does.
        * Field Name: An element or attribute name held by structure pointed
            to by the context label. For example, if the context label is
            'indicator:Indicator' a field name could be '@version' or
            'Title'. Attributes are prefaced by '@'.
        * Occurrence: These are typically, 'prohibited', 'required', 'optional'
            or 'suggested'. Rules are only created for 'required' and
            'prohibited' occurrence entries.
        * Implementation Type(s): These are allowed implementations of a
            ``Field Name``. This is often used to define controlled vocabulary
            or CybOX Object requirements. Example:
            ``stixVocabs:IndicatorType``. Multiple entries are comma delimited.
        * Allowed Value(s): Allowable values for a ``Field Name``. Examples
            are allowable `@version` values, or controlled vocabulary terms.

        Entries marked as ``Required`` may also have ``Allowed Value`` and
        ``Implementation Types`` tests applied to the field as well.

        Entries marked as ``Prohibited`` are only checked for presence. Any
        values found in the ``Implementation Types` or ``Allowed Values``
        fields will be ignored.

        Returns:
            A list of ``_BaseProfileRule`` implementations for the given
            rule parameters.  Because a ``Context Label`` can be mapped to
            multiple instance selectors, this method returns a list of rules
            for each selector. If a ``Context Label`` maps to only one
            selector, a list containing one element will be returned.

        """
        selectors = info.selectors
        ns_alias = info.ns_alias

        if not field.startswith("@"):
            # Elements must have a namespace alias attached which maps to
            # the defining namespace for the underlying data type of the
            # instance selector.
            fieldname = "%s:%s" % (ns_alias, field)
        else:
            fieldname = field

        rules = []
        for context in selectors:
            is_required = False

            if occurrence in OCCURRENCE_REQUIRED:
                is_required = True
                rule = RequiredRule(context, fieldname)
                rules.append(rule)
            elif occurrence in OCCURRENCE_PROHIBITED:
                rule = ProhibitedRule(context, fieldname)
                rules.append(rule)
                continue  # Cannot set prohibited values or impls
            elif occurrence in ALL_OPTIONAL_OCCURRENCES:
                pass
            else:
                continue

            if types:
                rule = AllowedImplsRule(context, fieldname, is_required, types)
                rules.append(rule)

            if values:
                rule = AllowedValuesRule(context, fieldname, is_required, values)
                rules.append(rule)

        return rules

    def _parse_worksheet_rules(self, worksheet, instance_map):
        """Parses the rules from the profile sheet `workheet`.

        Args:
            worksheet: A profile worksheet containing rules.
            instance_map: A dictionary representation of the ``Instance
                Mapping`` worksheet.

        Returns:
            A list of ``_BaseProfileRule`` implementations for the rules
            defined in the `worksheet`.

        Raises:
            .ProfileParseError: If a rule context label has no associated
                entry in `instance_map`.

        """
        value = functools.partial(self._get_value, worksheet)
        is_empty_row = functools.partial(self._is_empty_row, worksheet)

        def check_label(label):
            if label not in instance_map:
                err = (
                    "Worksheet '{0}' context label '{1}' has no Instance "
                    "Mapping entry."
                )
                raise errors.ProfileParseError(
                    err.format(worksheet.name, label)
                )

        all_rules = []
        for i in xrange(1, worksheet.nrows):
            if is_empty_row(i):
                continue

            if not value(i, COL_OCCURRENCE):
                ctx_label = value(i, COL_FIELD_NAME)
                check_label(ctx_label)
                continue

            field = value(i, COL_FIELD_NAME)
            occurrence = value(i, COL_OCCURRENCE).lower()
            types = value(i, COL_XSI_TYPES)
            values = value(i, COL_ALLOWED_VALUES)

            if occurrence not in ALLOWED_OCCURRENCES:
                err = "Found unknown occurrence '{0}' in worksheet '{1}'."
                raise errors.ProfileParseError(
                    err.format(occurrence, worksheet.name)
                )

            rules = self._build_rules(
                info=instance_map[ctx_label],
                field=field,
                occurrence=occurrence,
                types=types,
                values=values
            )

            all_rules.extend(rules)

        return all_rules

    def _parse_namespace_worksheet(self, worksheet):
        """Parses the Namespaces worksheet of a STIX profile. Returns a
        dictionary representation.

        ``d = { <namespace> : <namespace alias> }``

        By default, libxml2-required Saxon namespace is added to the return
        dictionary.

        """
        value = functools.partial(self._get_value, worksheet)
        is_empty_row = functools.partial(self._is_empty_row, worksheet)
        nsmap = {xmlconst.NS_SAXON: 'saxon'}

        def check_namespace(ns, alias):
            if not all((ns, alias)):
                raise errors.ProfileParseError(
                    "Missing namespace or alias: unable to parse Namespaces "
                    "worksheet"
                )

        for i in xrange(1, worksheet.nrows):  # skip the first row
            if is_empty_row(i):
                continue

            ns = value(i, COL_NAMESPACE)
            alias = value(i, COL_ALIAS)
            check_namespace(ns, alias)
            nsmap[ns] = alias

        return nsmap

    def _parse_instance_mapping_worksheet(self, worksheet, nsmap):
        """Parses the supplied Instance Mapping worksheet and returns a
        dictionary representation.

        Args:
            worksheet: The instance mapping worksheet of the profile.
            nsmap: The namespace dictionary derived from the ``Namespace``
                worksheet of the profile.

        Returns:
            A dictionary where the key is a Profile rule context label and the
            value is an instance of the :class:`InstanceMapping`.

        """
        value = functools.partial(self._get_value, worksheet)
        is_empty_row = functools.partial(self._is_empty_row, worksheet)
        instance_map = {}

        def check_label(label):
            if not label:
                raise errors.ProfileParseError(
                    "Found empty type label in Instance Mapping worksheet"
                )

            if label in instance_map:
                err = (
                    "Found duplicate type label in Instance Mapping "
                    "worksheet: '{0}'"
                )
                raise errors.ProfileParseError(err.format(label))

        for i in xrange(1, worksheet.nrows):
            if is_empty_row(i):
                continue

            label = value(i, COL_LABEL)
            check_label(label)

            mapping = InstanceMapping(nsmap)
            mapping.label = label
            mapping.namespace = value(i, COL_TYPE_NAMESPACE)
            mapping.selectors = value(i, COL_SELECTORS)
            mapping.validate()

            instance_map[label] = mapping

        return instance_map

    def _parse_workbook_rules(self, workbook, instance_map):
        """Parses all worksheets contained in `workbook` which contain
        profile rules. This will skip over the 'Overview', 'Namespace', and
        'Instance Mapping' worksheets.

        Args:
            workbook: The profile Excel workbook.
            instance_map: A dictionary representation of the
                ``Instance Mapping`` worksheet.

        Returns:
            A list of ``_BaseProfileRule`` implementations containing every
            rule in the `workbook` profile.

        """
        skip = ("Overview", "Namespaces", "Instance Mapping")

        rules = []
        for worksheet in workbook.sheets():
            if worksheet.name in skip:
                continue

            wksht_rules = self._parse_worksheet_rules(worksheet, instance_map)
            rules.extend(wksht_rules)

        return rules

    @contextlib.contextmanager
    def _parse_profile(self, profile_fn):
        """Converts the supplied STIX profile into a Schematron representation.
         The Schematron schema is returned as a etree._Element instance.

        Args:
            workbook: The profile Excel workbook.

        Returns:
            A Schematron ``etree._Element`` instance.

        Raises:
            .ProfileParseError: If `profile_fn` does not point to a valid
                STIX profile or an error occurs while parsing the STIX profile.

        """
        workbook = self._open_workbook(profile_fn)
        ws = workbook.sheet_by_name

        try:
            namespaces = self._parse_namespace_worksheet(ws("Namespaces"))
            instance_mapping = self._parse_instance_mapping_worksheet(
                ws("Instance Mapping"), namespaces
            )
            rules = self._parse_workbook_rules(workbook, instance_mapping)

            profile = Profile(namespaces)
            profile.extend(rules)
            yield profile.as_etree()
        except xlrd.XLRDError as ex:
            err = "Error occurred while parsing STIX Profile: %s" % str(ex)
            raise errors.ProfileParseError(err)
        finally:
            self._unload_workbook(workbook)

    def _unload_workbook(self, workbook):
        """Unloads the xlrd workbook."""
        for worksheet in workbook.sheets():
            workbook.unload_sheet(worksheet.name)

    def _is_empty_row(self, worksheet, row):
        """Returns true if the `row` in `worksheet` does not contain any values
        in any columns.

        """
        return not any(
            self._get_value(worksheet, row, x) for x in xrange(worksheet.ncols)
        )

    def _get_value(self, worksheet, row, col):
        """Returns the worksheet cell value found at (row,col)."""
        if not worksheet:
            raise errors.ProfileParseError("worksheet value was NoneType")

        return str(worksheet.cell_value(row, col))

    def _open_workbook(self, filename):
        """Returns xlrd.open_workbook(filename) or raises an Exception if the
        filename extension is not .xlsx or the open_workbook() call fails.

        """
        if not filename.lower().endswith(".xlsx"):
            raise errors.ProfileParseError(
                "Profile must have .XLSX extension. Filename provided: '%s'" %
                filename
            )

        if not os.path.exists(filename):
            raise errors.ProfileParseError(
                "The profile document '%s' does not exist" % filename
            )

        try:
            return xlrd.open_workbook(filename)
        except:
            raise errors.ProfileParseError(
                "Error occurred while opening '%s'. File may be an invalid or "
                "corrupted XSLX document."
            )

    @schematron.SchematronValidator.xslt.getter
    def xslt(self):
        """Returns an lxml.etree._ElementTree representation of the ISO
        Schematron skeleton generated XSLT translation of a STIX profile.

        The STIXProfileValidator uses the extension function
        saxon:line-number() for reporting line numbers. This function is
        stripped along with any references to the Saxon namespace from the
        exported XSLT. This is due to compatibility issues between
        Schematron/XSLT processing libraries. For example, SaxonPE/EE expects
        the Saxon namespace to be "http://saxon.sf.net/" while libxslt expects
        it to be "http://icl.com/saxon". The freely distributed SaxonHE
        library does not support Saxon extension functions at all.

        Returns:
            An ``etree._ElementTree`` XSLT document.

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

        return etree.parse(StringIO.StringIO(s))

    @schematron.SchematronValidator.schematron.getter
    def schematron(self):
        """Returns an lxml.etree._ElementTree representation of the
        ISO Schematron translation of a STIX profile.

        The STIXProfileValidator uses the extension function
        saxon:line-number() for reporting line numbers. This function is
        stripped along with any references to the Saxon namespace from the
        exported XSLT. This is due to compatibility issues between
        Schematron/XSLT processing libraries. For example, SaxonPE/EE expects
        the Saxon namespace to be "http://saxon.sf.net/" while libxslt expects
        it to be "http://icl.com/saxon". The freely distributed SaxonHE
        library does not support Saxon extension functions at all.

        Returns:
            An ``etree._ElementTree`` Schematron document.

        """
        to_replace = ' %s' % SAXON_LINENO

        s = etree.tostring(self._schematron.schematron)
        s = s.replace(to_replace, '')
        s = s.replace('<ns prefix="saxon" uri="http://icl.com/saxon"/>', '')

        return etree.parse(StringIO.StringIO(s))

    @common.check_stix
    def validate(self, doc):
        """Validates an XML instance document against a STIX profile.

        Args:
            doc: The STIX document. This can be a filename, file-like object,
                ``etree._Element``, or ``etree._ElementTree`` instance.

        Returns:
            An instance of
            :class:`.ProfileValidationResults`.

        Raises:
            .ValidationError: If there are any issues parsing `doc`.

        """
        root = utils.get_etree_root(doc)
        is_valid = self._schematron.validate(root)
        svrl_report = self._schematron.validation_report

        return ProfileValidationResults(is_valid, root, svrl_report)


__all__ = [
    'STIXProfileValidator',
    'ProfileError',
    'ProfileValidationResults'
]
