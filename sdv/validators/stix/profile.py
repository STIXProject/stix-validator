# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import os
import itertools
import collections
import functools
from io import StringIO

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

# Used to get the name of the context node.
NAME = '<value-of select="name()"/>'


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
        elif isinstance(value, str):
            self._selectors = [x.strip().replace('"', "'") for x in value.split(",")]
        elif hasattr(value, "__iter__"):
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
        elif value in self._nsmap:
            self._namespace = value
            self._ns_alias = self._nsmap[value]
        else:
            err = "Unable to map namespace '{ns}' to namespace alias"
            raise errors.ProfileParseError(err.format(ns=value))

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
            err = "Missing type label in Instance Mapping"
            raise errors.ProfileParseError(err)

        if not self.namespace:
            err = "Missing namespace for '{label}'' in Instance Mapping worksheet"
            raise errors.ProfileParseError(err.format(label=self.label))

        if not (self.selectors and all(self.selectors)):
            err = ("Empty selector for '{label}' in Instance Mapping worksheet. "
                   "Look for extra commas in field.")
            raise errors.ProfileParseError(err.format(label=self.label))


class Profile(collections.abc.MutableSequence):
    def __init__(self, namespaces):
        self.id = "STIX_Schematron_Profile"
        self._rules = [RootRule(namespaces)]
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

        for rule in self:
            collected[rule.context_selector].append(rule)

        return collected

    @property
    def rules(self):
        """Builds and returns a dictionary of ``BaseProfileRule``
        implementations. The key is the Rule context.

        """
        notype  = schematron.make_pattern("no-type")
        typed   = schematron.make_pattern("xsi-typed")
        rules   = [notype, typed]

        collected = self._collect_rules()
        for ctx, profile_rules in collected.items():
            rule = schematron.make_rule(ctx)
            rule.extend(x.as_etree() for x in profile_rules)

            if "@xsi:type=" in utils.strip_whitespace(ctx):
                typed.append(rule)
            else:
                notype.append(rule)

        return rules

    @property
    def namespaces(self):
        """Returns a list of etree Elements that represent Schematron
        ``<ns prefix='foo' uri='bar'>`` elements.

        """
        namespaces = []

        for ns, prefix in self._namespaces.items():
            ns = schematron.make_ns(prefix, ns)
            namespaces.append(ns)

        return namespaces

    def as_etree(self):
        """Returns an etree Schematron document for this ``Profile``."""
        schema = schematron.make_schema()
        schema.extend(self.namespaces)
        schema.extend(self.rules)
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
    TYPE_REPORT  = "report"
    TYPE_ASSERT  = "assert"

    def __init__(self, field, instance_mapping):
        self._instance_mapping = instance_mapping
        self._type = None
        self._role = "error"
        self._context = utils.union(instance_mapping.selectors)
        self.field = field

    def _validate(self):
        """Perform validation/sanity checks on the input values."""
        pass

    @property
    def field(self):
        return self._field

    @field.setter
    def field(self, value):
        if value.startswith("@"):
            self._field = value
        elif ":" in value:
            self._field = value
        else:
            prefix = self._instance_mapping.ns_alias
            self._field = "%s:%s" % (prefix, value)

    def typens(self):
        return self._instance_mapping.namespace

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
        kwargs = {
            'type': self.type,              # 'assert' or 'report'
            'ns': xmlconst.NS_SCHEMATRON,   # schematron namespace
            'test': self.test,              # test selector
            'role': self.role,              # "error"
            'message': self.message,        # error message
            'line': SAXON_LINENO            # line number function
        }

        xml = '<{type} xmlns="{ns}" test="{test}" role="{role}">{message} {line}</{type}>'
        rule = etree.XML(xml.format(**kwargs))
        return rule


class RequiredRule(_BaseProfileRule):
    """Represents a profile rule which requires the presence of an element
    or attribute.

    This serializes to a Schematron ``<assert>`` directive as
    it will raise an error if the field is **not** found in the instance
    document.
    """

    def __init__(self, field, instance_mapping):
        super(RequiredRule, self).__init__(field, instance_mapping)
        self._type = self.TYPE_ASSERT

    @_BaseProfileRule.test.getter
    def test(self):
        return self.field

    @_BaseProfileRule.context_selector.getter
    def context_selector(self):
        return self._context

    @_BaseProfileRule.test.getter
    def message(self):
        msg = "{parent}/{field} is required by this profile."
        return msg.format(parent=NAME, field=self.field)


class ProhibitedRule(_BaseProfileRule):
    """Represents a profile rule which prohibits the use of a particular
    attribute or field.

    This serializes to a Schematron ``<report>`` directive
    as it will raise an error if the field **is found** in the instance
    document.

    """

    def __init__(self, field, instance_mapping):
        super(ProhibitedRule, self).__init__(field, instance_mapping)
        self._type = self.TYPE_REPORT

    @_BaseProfileRule.test.getter
    def test(self):
        return self.field

    @_BaseProfileRule.context_selector.getter
    def context_selector(self):
        return self._context

    @_BaseProfileRule.message.getter
    def message(self):
        msg = "{parent}/{field} is prohibited by this profile."
        return msg.format(parent=NAME, field=self.field)


class AllowedValuesRule(_BaseProfileRule):
    """Represents a profile rule which requires that a field value be one
    of a defined set of allowed values.

    This serializes to a schematron ``<assert>`` directive.

    """

    def __init__(self, field, instance_mapping, required=True, values=None):
        super(AllowedValuesRule, self).__init__(field, instance_mapping)
        self._type = self.TYPE_ASSERT
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
        elif isinstance(value, str):
            self._values = [x.strip() for x in value.split(',')]
        elif hasattr(value, "__getitem__"):
            self._values = [str(x) for x in value]
        else:
            self._values = [value]

    @_BaseProfileRule.context_selector.getter
    def context_selector(self):
        return self._context

    @_BaseProfileRule.message.getter
    def message(self):
        msg = "The allowed values for {parent}/{field} are {values}."
        return msg.format(parent=NAME, field=self.field, values=self.values)

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
        test = " or ".join("%s='%s'" % (self.field, x) for x in self.values)

        if not self.is_required:
            test = "not({field}) or {values}".format(field=self.field, values=test)

        return test

class AllowedImplsRule(_BaseProfileRule):
    def __init__(self, field, instance_mapping, required=True, impls=None):
        super(AllowedImplsRule, self).__init__(field, instance_mapping)
        self._type = self.TYPE_ASSERT
        self.is_required = required
        self.impls = impls

    def _validate(self):
        if not self.is_attr:
            return

        err = ("Implementation rules cannot be applied to attribute fields: "
               "{0}".format(self.path))
        raise errors.ProfileParseError(err)

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
        elif isinstance(value, str):
            self._impls = [x.strip() for x in value.split(',')]
        elif hasattr(value, "__iter__"):
            self._impls = [str(x) for x in value]
        else:
            self._impls = [value]

    @_BaseProfileRule.context_selector.getter
    def context_selector(self):
        return self._context

    @_BaseProfileRule.message.getter
    def message(self):
        msg = "The allowed implementations for {parent}/{field} are {types}"
        return msg.format(parent=NAME, field=self.field, types=self.impls)

    @_BaseProfileRule.test.getter
    def test(self):
        """Returns a test to check that a field implementation is set to
        one of the allowable values.

        This expects the ``<assert>`` directive to be places within a rule
        where the selector is the field name if this rule applies to an
        element name.
        """
        notype = "not({field}/@xsi:type)".format(field=self.field)
        types  = " or ".join("%s/@xsi:type='%s'" % (self.field, x) for x in self.impls)
        test   = "{notype} or {types}".format(notype=notype, types=types)

        if not self.is_required:
            test = "not({field}) or {impls}".format(field=self.field, impls=test)

        return test

class RootRule(RequiredRule):
    def __init__(self, nsmap):
        mapping = InstanceMapping(nsmap=nsmap)
        mapping.selectors = "/"
        mapping.namespace = "http://stix.mitre.org/stix-1"

        super(RootRule, self).__init__(
            field="stix:STIX_Package",
            instance_mapping=mapping
        )

    @_BaseProfileRule.test.getter
    def test(self):
        return self.field

    @_BaseProfileRule.context_selector.getter
    def context_selector(self):
        return self._context

    @_BaseProfileRule.message.getter
    def message(self):
        return "The root element must be a STIX_Package instance"


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
        self._line = self._parse_line(error.node)

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
        errors = self._get_errors(svrl_report)
        return [ProfileError(self._doc, x) for x in errors]


class STIXProfileValidator(schematron.SchematronValidator):
    """Performs STIX Profile validation.

    Args:
        profile_fn: The filename of a ``.xlsx`` STIX Profile document.
    """

    def __init__(self, profile_fn):
        profile = self._parse_profile(profile_fn)
        super(STIXProfileValidator, self).__init__(schematron=profile.as_etree())

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

        Entries marked as ``Optional`` or ``Suggested`` are skipped unless
        there are associated allowed values/fields. Generated rules will
        validate values/implementations if the fields are found in the document.

        Entries marked as ``Prohibited`` are only checked for presence. Any
        values found in the ``Implementation Types` or ``Allowed Values``
        fields will be ignored.

        Returns:
            A list of ``_BaseProfileRule`` implementations for the given
            rule parameters.
        """
        is_required = False
        rules       = []

        if occurrence in OCCURRENCE_REQUIRED:
            is_required = True
        elif occurrence in OCCURRENCE_PROHIBITED:
            rule = ProhibitedRule(field, info)
            rules.append(rule)
        elif occurrence in ALL_OPTIONAL_OCCURRENCES:
            pass
        else:
            return rules

        if types:
            rule = AllowedImplsRule(field, info, is_required, types)
            rules.append(rule)

        if values:
            rule = AllowedValuesRule(field, info, is_required, values)
            rules.append(rule)

        # Allowed value/impl rules will check for existence if the field is
        # required, so we don't need an explicit existence check as well.
        if is_required and not(types or values):
            rule = RequiredRule(field, info)
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
        for i in range(1, worksheet.nrows):
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
        value    = functools.partial(self._get_value, worksheet)
        is_empty = functools.partial(self._is_empty_row, worksheet)
        nsmap    = {xmlconst.NS_SAXON: 'saxon'}

        def check_namespace(ns, alias):
            if ns and alias:
                return

            err = ("Missing namespace or alias: unable to parse Namespaces "
                   "worksheet")
            raise errors.ProfileParseError(err)

        for row in range(1, worksheet.nrows):  # skip the first row
            if is_empty(row):
                continue

            ns = value(row, COL_NAMESPACE)
            alias = value(row, COL_ALIAS)
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
        value        = functools.partial(self._get_value, worksheet)
        is_empty     = functools.partial(self._is_empty_row, worksheet)
        instance_map = {}

        def check_label(label):
            if not label:
                err = "Found empty type label in Instance Mapping worksheet"
                raise errors.ProfileParseError(err)

            if label not in instance_map:
                return

            err = ("Found duplicate type label in Instance Mapping worksheet: "
                   "'{label}'")
            raise errors.ProfileParseError(err.format(label=label))

        for row in range(1, worksheet.nrows):
            if is_empty(row):
                continue

            label = value(row, COL_LABEL)
            check_label(label)

            mapping = InstanceMapping(nsmap)
            mapping.label = label
            mapping.namespace = value(row, COL_TYPE_NAMESPACE)
            mapping.selectors = value(row, COL_SELECTORS)
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
                worksheet=ws("Instance Mapping"),
                nsmap=namespaces
            )

            rules = self._parse_workbook_rules(workbook, instance_mapping)
            profile = Profile(namespaces)
            profile.extend(rules)
            return profile
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
        cols = range(worksheet.ncols)
        return not any(self._get_value(worksheet, row, col) for col in cols)

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
            err = "Profile must have .XLSX extension. Filename provided: '{fn}'"
            raise errors.ProfileParseError(err.format(fn=filename))

        if not os.path.exists(filename):
            err = "The profile document '{fn}' does not exist"
            raise errors.ProfileParseError(err.format(fn=filename))

        try:
            return xlrd.open_workbook(filename)
        except:
            err = ("Error occurred while opening '{fn}'. File may be an invalid "
                   "or corrupted XSLX document.")
            raise errors.ProfileParseError(err.format(fn=filename))

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
        s = s.replace(' [<axsl:text/><axsl:value-of select="saxon:line-number()"/><axsl:text/>]', '')
        s = s.replace('xmlns:saxon="http://icl.com/saxon"', '')
        s = s.replace('<svrl:ns-prefix-in-attribute-values uri="http://icl.com/saxon" prefix="saxon"/>', '')

        parser = utils.get_xml_parser()
        return etree.parse(StringIO(s), parser=parser)

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

        parser = utils.get_xml_parser()
        return etree.parse(StringIO(s), parser=parser)

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
        results = ProfileValidationResults(is_valid, root, svrl_report)
        return results

__all__ = [
    'STIXProfileValidator',
    'ProfileError',
    'ProfileValidationResults'
]
