# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import re
import itertools
import collections
from packaging.version import parse as parse_version

# external
from lxml import etree

# internal
from sdv import utils, xmlconst

# relative
from . import common
from .. import base
from ...utils import remove_version_prefix


# STIX ID Format: [ns prefix]:[construct type]-[GUID]
# Note: This will validate invalid QNames, so this should be used with a
# QName format check.
ID_PATTERN = re.compile(r"[\w\-]+:\w+-.+", re.UNICODE)


def rule(minver, maxver=None):
    """Decorator that identifies methods as being a STIX best practice checking
    rule.

    Args:
        version: Identifies the minimum version of STIX for which the decorated
            method applies.
    """
    def decorator(func):
        func.is_rule = True
        func.min_version = minver
        func.max_version = maxver
        return func
    return decorator


class BestPracticeMeta(type):
    """Metaclass that collects all :meth:`rule` decorated methods and
    builds an internal mapping of STIX version numbers to rules.

    """
    def __new__(metacls, name, bases, dict_):
        obj = type.__new__(metacls, name, bases, dict_)

        # Initialize a mapping of STIX versions to applicable rule funcs.
        ruledict = collections.defaultdict(list)

        # Find all @rule marked functions in the class dict_
        rulefuncs = (x for x in dict_.values() if hasattr(x, 'is_rule'))

        # Build the rule function dict.
        for rule in rulefuncs:
            ruledict[(rule.min_version, rule.max_version)].append(rule)  # noqa

        # Attach the rule dictionary to the object instance.
        obj._rules = ruledict  # noqa

        return obj


class BestPracticeWarning(collections.abc.MutableMapping, base.ValidationError):
    """Represents a best practice warning. These are built within best
    practice rule checking methods and attached to
    :class:`BestPracticeWarningCollection` instances.

    Note:
        This class acts like a dictionary and contains the following keys
        at a minimum:

        * ``'id'``: The id of a node associated with the warning.
        * ``'idref'``: The idref of a node associated with the warning.
        * ``'line'``: The line number of the offending node.
        * ``'message'``: A message associated with the warning.
        * ``'tag'``: The lxml tag for the offending node.

        These keys can be retrieved via the :attr:`core_keys` property.

        Instances of this class may attach additional keys. These `other keys`
        can be obtained via the :attr:`other_keys` property.

    Args:
        node: The ``lxml._Element`` node associated with this warning.
        message: A message for this warning.

    """
    def __init__(self, node, message=None):
        base.ValidationError.__init__(self)

        self._inner = collections.OrderedDict()
        self._node = node

        self['line'] = node.sourceline
        self['message'] = message
        self['id'] = node.attrib.get('id')
        self['idref'] = node.attrib.get('idref')
        self['tag'] = node.tag

    def __unicode__(self):
        return unicode(self.message)

    def __str__(self):
        return unicode(self).encode("utf-8")

    def __getitem__(self, key):
        return self._inner.__getitem__(key)

    def __delitem__(self, key):
        self._inner.__delitem__(key)

    def __setitem__(self, key, value):
        self._inner.__setitem__(key, value)

    def __len__(self):
        return self._inner.__len__()

    def __iter__(self):
        return self._inner.__iter__()

    @property
    def line(self):
        """Returns the line number of the warning node in the input document.

        """
        return self['line']

    @property
    def message(self):
        """Returns a message associated with the warning. This may return
        ``None`` if there is no warning message.

        """
        return self['message']

    @property
    def core_keys(self):
        """Returns a ``tuple`` of  the keys that can always be found on
        instance of this class.

        Returns:
            A tuple including the following keys.

            * ``'id'``: The id of the warning node. The associated value
              may be ``None``.
            * ``'idref'``: The idref of the warning node. The associated value
              may be ``None``.
            * ``'line'``: The line number of the warning node in the input
              document. The associated value may be ``None``.
            * ``'tag'``: The ``{namespace}localname`` value of the warning
              node.
            * ``'message'``: An optional message that can be attached to the
              warning. The associated value may be ``None``.
        """
        return ('id', 'idref', 'line', 'tag', 'message')

    @property
    def other_keys(self):
        """Returns a ``tuple`` of keys attached to instances of this class that
        are not found in the :attr:`core_keys`.

        """
        return tuple(x for x in self if x not in self.core_keys)

    def as_dict(self):
        """Returns a dictionary representation of this class instance. This
        is implemented for consistency across other validation error types.

        The :class:`.BestPracticeWarning` class extends
        :class:`collections.MutableMapping`, so this method isn't really
        necessary.

        """
        return dict(self.items())


class BestPracticeWarningCollection(collections.abc.MutableSequence):
    """A collection of :class:`BestPracticeWarning` instances for a given
    type of STIX Best Practice.

    For example, all warnings about STIX constructs missing titles would
    go within an instance of this class.

    Note:
        This class behaves like a mutable sequence, such as a ``list``.

    Args:
        name: The name of the STIX best practice for this collection (e.g.,
            'Missing Titles').

    Attributes:
        name: The name of the STIX best practice for this collection (e.g.,
            'Missing Titles').

    """
    def __init__(self, name):
        super(BestPracticeWarningCollection, self).__init__()
        self.name = name
        self._warnings = []

    def insert(self, idx, value):
        """Inserts `value` at `idx` into this
        :class:`BestPracticeWarningCollection` instance.

        Note:
            Values that evaluate to ``False`` will not be inserted.

        """
        if not value:
            return

        if isinstance(value, etree._Element):  # noqa
            value = BestPracticeWarning(node=value)

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
        """Returns a dictionary representation.

        The key of the dictionary is the ``name`` of this collection. The
        associated value is a ``list`` of :class:`BestPracticeWarning`
        dictionaries.

        """
        if not self:
            return {}

        return {self.name: [x.as_dict() for x in self]}


class BestPracticeValidationResults(base.ValidationResults, collections.abc.MutableSequence):
    """Represents STIX best practice validation results. This class behaves
    like a ``list`` and accepts instances of
    :class:`BestPracticeWarningCollection`.

    """
    def __init__(self):
        base.ValidationResults.__init__(self, False)

        self._warnings = []

    @base.ValidationResults.is_valid.getter
    def is_valid(self):
        """Returns ``True`` if an instance of this class contains no warning
        collections or only contains only warning collections.

        """
        return not(any(self))

    @property
    def errors(self):
        """Returns a ``list`` of :class:`BestPracticeWarningCollection`
        instances.

        """
        return [x for x in self if x]

    def insert(self, idx, value):
        """Inserts an instance of :class:`BestPracticeWarningCollection`.

        Note:
            If ``bool(value) == False`` then `value` will not be inserted.

        Raises:
            ValueError: If `value` is not an instance of
                :class:`BestPracticeWarningCollection`.

        """
        if not value:
            return

        if not isinstance(value, BestPracticeWarningCollection):
            raise ValueError(
                "Value must be instance of BestPracticeWarningCollection"
            )

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
        """Returns a dictionary representation.

        Keys:
            * ``'result'``: The result of the validation. Values can be
              ``True`` or ``False`` .
            * ``'errors'``: A list of :class:`BestPracticeWarningCollection`
              dictionaries.

        """
        d = base.ValidationResults.as_dict(self)

        if any(self):
            d['errors'] = [x.as_dict() for x in self if x]

        return d


class STIXBestPracticeValidator(object, metaclass=BestPracticeMeta):
    """Performs STIX Best Practice validation."""

    @rule('1.0')
    def _check_id_presence(self, root, namespaces, version):  # noqa
        """Checks that all major STIX/CybOX constructs have id attributes set.
        Constructs with idref attributes set should not have an id attribute
        and are thus omitted from the results.

        """
        to_check = itertools.chain(
            common.STIX_CORE_COMPONENTS,
            common.CYBOX_CORE_COMPONENTS
        )

        results = BestPracticeWarningCollection('Missing IDs')
        xpath = " | ".join("//%s" % x for x in to_check)
        nodes = root.xpath(xpath, namespaces=namespaces)

        for node in nodes:
            if any(x in node.attrib for x in ('id', 'idref')):
                continue

            warning = BestPracticeWarning(node=node)
            results.append(warning)

        return results

    @rule('1.0')
    def _check_id_format(self, root, namespaces, version):  # noqa
        """Checks that the core STIX/CybOX constructs in the STIX instance
        document have ids and that each id is a valid QName, formatted as
        follows:

        ``[ns_prefix]:[object-type]-[GUID].``

        Note:
            This only checks for STIX ID best practices and does not verify
            that the ID is a valid QName. QName conformance verification is
            done during XML Schema validation.

        """
        to_check = itertools.chain(
            common.STIX_CORE_COMPONENTS,
            common.CYBOX_CORE_COMPONENTS
        )

        results = BestPracticeWarningCollection('ID Format')
        msg = "ID should be formatted as [ns prefix]:[construct type]-[GUID]"
        xpath = " | ".join("//%s[@id]" % x for x in to_check)

        for node in root.xpath(xpath, namespaces=namespaces):
            id_ = node.attrib['id']

            if ID_PATTERN.match(id_):
                continue

            result = BestPracticeWarning(node=node, message=msg)
            results.append(result)

        return results

    def _get_id_timestamp_conflicts(self, nodes):
        """Returns a list of BestPracticeWarnings for all nodes in `nodes`
        that have duplicate (id, timestamp) pairs.

        """
        warns = []

        def _equal_timestamps(nodeset):
            return [x for x in nodeset if utils.is_equal_timestamp(node, x)]

        while len(nodes) > 1:
            node = nodes.pop()
            ts_equal = _equal_timestamps(nodes)

            if not ts_equal:
                continue

            conflicts = itertools.chain(ts_equal, (node,))

            for c in conflicts:
                warning = BestPracticeWarning(node=c)
                warning['timestamp'] = c.attrib.get('timestamp')
                warns.append(warning)

            utils.remove_all(nodes, ts_equal)

        return warns

    @rule('1.2')
    def _check_1_2_duplicate_ids(self, root, namespaces, version):  # noqa
        """STIX 1.2 dropped the schematic enforcement of id uniqueness to
        support versioning of components.

        This checks for duplicate (id, timestamp) pairs.

        """
        results = BestPracticeWarningCollection('Duplicate IDs')
        nlist = namespaces.values()

        # Find all nodes with IDs in the STIX/CybOX namespace
        nodes = root.xpath("//*[@id]")
        filtered = [x for x in nodes if utils.namespace(x) in nlist]

        # Build a mapping of IDs to nodes
        idnodes = collections.defaultdict(list)
        for node in filtered:
            idnodes[node.attrib.get('id')].append(node)

        # Find all nodes that have duplicate IDs
        dups = [x for x in idnodes.values() if len(x) > 1]

        # Build warnings for all nodes that have conflicting id/timestamp pairs.
        for nodeset in dups:
            warns = self._get_id_timestamp_conflicts(nodeset)
            results.extend(warns)

        return results

    @rule(minver='1.0', maxver='1.1.1')
    def _check_1_0_duplicate_ids(self, root, namespaces, version):  # noqa
        """Checks for duplicate ids in the document.

        """
        id_nodes = collections.defaultdict(list)

        for node in root.xpath("//*[@id]"):
            id_nodes[node.attrib['id']].append(node)

        results = BestPracticeWarningCollection('Duplicate IDs')
        for nodes in id_nodes.values():
            if len(nodes) > 1:
                results.extend(BestPracticeWarning(node=x) for x in nodes)

        return results

    @rule('1.0')
    def _check_idref_resolution(self, root, namespaces, version):  # noqa
        """Checks that all idrefs resolve to a construct in the document.

        """
        idrefs = root.xpath("//*[@idref]")
        ids = root.xpath("//@id")

        def idref(x):
            return x.attrib['idref']

        results = BestPracticeWarningCollection("Unresolved IDREFs")
        warns = (BestPracticeWarning(x) for x in idrefs if idref(x) not in ids)
        results.extend(warns)

        return results

    @rule('1.0')
    def _check_idref_with_content(self, root, namespaces, version):  # noqa
        """Checks that constructs with idref set do not contain content.

        Note:
            Some STIX/CybOX constructs (e.g., ``Related_Object`` instances) are
            exceptions to this rule.

        """
        def is_invalid(node):
            if common.is_idref_content_exception(node):
                return False

            return utils.has_content(node)

        nodes = root.xpath("//*[@idref]")
        warnings = (BestPracticeWarning(x) for x in nodes if is_invalid(x))

        results = BestPracticeWarningCollection("IDREF with Content")
        results.extend(warnings)

        return results

    @rule('1.0')
    def _check_indicator_practices(self, root, namespaces, version):  # noqa
        """Looks for STIX Indicators that are missing a Description, Type,
        Valid_Time_Position, Indicated_TTP, and/or Confidence.

        """
        to_check = (
            "{0}:Indicator".format(common.PREFIX_STIX_CORE),
            "{0}:Indicator".format(common.PREFIX_STIX_COMMON),
            "{0}:Indicator".format(common.PREFIX_STIX_REPORT),
        )

        results = BestPracticeWarningCollection("Indicator Suggestions")
        xpath = " | ".join("//%s" % x for x in to_check)
        ns = namespaces[common.PREFIX_STIX_INDICATOR]

        for indicator in root.xpath(xpath, namespaces=namespaces):
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

    @rule('1.0')
    def _check_root_element(self, root, namespaces, version):  # noqa
        """Checks that the root element is a STIX_Package.

        """
        ns = namespaces[common.PREFIX_STIX_CORE]
        results = BestPracticeWarningCollection("Root Element")

        if root.tag != "{%s}STIX_Package" % (ns):
            warning = BestPracticeWarning(node=root)
            results.append(warning)

        return results

    @rule('1.0')
    def _check_latest_vocabs(self, root, namespaces, version):  # noqa
        """Checks that all STIX vocabs are using latest published versions.
        Triggers a warning if an out of date vocabulary is used.

        Note:
            The xpath used to discover instances of controlled vocabularies
            assumes that the type name ends with 'Vocab-'. An example
            instance would be 'IndicatorTypeVocab-1.0'.

        """
        results = BestPracticeWarningCollection("Vocab Suggestions")
        xpath = "//*[contains(@xsi:type, 'Vocab-')]"

        for vocab in root.xpath(xpath, namespaces=namespaces):
            xsi_type = vocab.attrib[xmlconst.TAG_XSI_TYPE]
            name = common.parse_vocab_name(xsi_type)
            found = common.parse_vocab_version(xsi_type)
            expected = common.get_vocab_version(root, version, xsi_type)

            if found == expected:
                continue

            warning = BestPracticeWarning(node=vocab)
            warning['vocab name'] = name
            warning['version found'] = found
            warning['version expected'] = expected
            results.append(warning)

        return results

    @rule('1.0')
    def _check_latest_versions(self, root, namespaces, version):  # noqa
        """Checks that all major STIX constructs versions are equal to
        the latest version.

        """
        to_check = common.STIX_COMPONENT_VERSIONS[version]
        results = BestPracticeWarningCollection('Latest Component Versions')

        def _is_expected(node, expected):
            if 'version' not in node.attrib:
                return True
            return node.attrib['version'] == expected

        for selector, expected in to_check.items():
            xpath = "//%s" % selector

            for node in root.xpath(xpath, namespaces=namespaces):
                if _is_expected(node, expected):
                    continue

                warning = BestPracticeWarning(node)
                warning['version found'] = node.attrib['version']
                warning['version expected'] = expected
                results.append(warning)

        return results

    def _check_timestamp_usage(self, root, namespaces, selectors):
        """Inspects each node in `nodes` for correct timestamp use.

        """
        results = BestPracticeWarningCollection("Timestamp Use")
        xpath = " | ".join("//%s" % x for x in selectors)
        nodes = root.xpath(xpath, namespaces=namespaces)

        for node in nodes:
            attrib      = node.attrib.get
            id_         = attrib('id')
            idref       = attrib('idref')
            timestamp   = attrib('timestamp')

            if timestamp:
                tz_set = utils.has_tzinfo(timestamp)

                if not tz_set:
                    warning = BestPracticeWarning(
                        node = node,
                        message="Timestamp without timezone information."
                    )
                    warning['timestamp'] = timestamp
                    results.append(warning)

            if id_ and not timestamp:
                warning = BestPracticeWarning(
                    node=node,
                    message="ID present but missing timestamp"
                )
            elif idref and not timestamp:
                warning = BestPracticeWarning(
                    node=node,
                    message="IDREF present but missing timestamp"
                )
            elif idref and timestamp:
                resolves = common.idref_timestamp_resolves(
                    root=root,
                    idref=idref,
                    timestamp=timestamp,
                    namespaces=namespaces
                )

                if resolves:
                    continue

                warning = BestPracticeWarning(
                    node=node,
                    message="IDREF and timestamp combination do not resolve "
                            "to a node in the input document."
                )

                warning['timestamp'] = timestamp
            else:
                continue

            results.append(warning)

        return results

    @rule(minver='1.1', maxver='1.1.1')
    def _check_1_1_timestamp_usage(self, root, namespaces, **kwargs):  # noqa
        """Checks that all major STIX constructs have appropriate
        timestamp usage.

        Note:
            This does not check core CybOX constructs because they lack
            timestamp attributes.

        """
        to_check = common.STIX_CORE_COMPONENTS
        results = self._check_timestamp_usage(root, namespaces, to_check)
        return results

    @rule('1.2')
    def _check_1_2_timestamp_usage(self, root, namespaces, **kwargs):  # noqa
        """Checks that all major STIX constructs have appropriate
        timestamp usage.

        Note:
            This does not check core CybOX constructs because they lack
            timestamp attributes.

        """
        to_check = common.STIX_CORE_COMPONENTS[2:]  # skip STIX Packages
        results = self._check_timestamp_usage(root, namespaces, to_check)
        return results

    def _check_titles(self, root, namespaces, selectors):
        """Checks that each node in `nodes` has a ``Title`` element unless
        there is an ``@idref`` attribute set.

        """
        results = BestPracticeWarningCollection("Missing Titles")
        xpath = " | ".join("//%s" % x for x in selectors)
        nodes = root.xpath(xpath, namespaces=namespaces)

        for node in nodes:
            if 'idref' in node.attrib:
                continue

            if not any(utils.localname(x) == 'Title' for x in utils.iterchildren(node)):
                warning = BestPracticeWarning(node=node)
                results.append(warning)

        return results

    @rule(minver='1.0', maxver='1.1.1')
    def _check_1_0_titles(self, root, namespaces, version):  # noqa
        """Checks that all major STIX constructs have a Title element.

        """
        to_check = (
            '{0}:STIX_Package/{0}:STIX_Header'.format(common.PREFIX_STIX_CORE),
            '{0}:Campaign'.format(common.PREFIX_STIX_CORE),
            '{0}:Campaign'.format(common.PREFIX_STIX_COMMON),
            '{0}:Course_Of_Action'.format(common.PREFIX_STIX_CORE),
            '{0}:Course_Of_Action'.format(common.PREFIX_STIX_COMMON),
            '{0}:Exploit_Target'.format(common.PREFIX_STIX_CORE),
            '{0}:Exploit_Target'.format(common.PREFIX_STIX_COMMON),
            '{0}:Incident'.format(common.PREFIX_STIX_CORE),
            '{0}:Incident'.format(common.PREFIX_STIX_COMMON),
            '{0}:Indicator'.format(common.PREFIX_STIX_CORE),
            '{0}:Indicator'.format(common.PREFIX_STIX_COMMON),
            '{0}:Threat_Actor'.format(common.PREFIX_STIX_COMMON),
            '{0}:Threat_Actor'.format(common.PREFIX_STIX_CORE),
            '{0}:TTP'.format(common.PREFIX_STIX_CORE),
            '{0}:TTP'.format(common.PREFIX_STIX_COMMON)
        )

        results = self._check_titles(root, namespaces, to_check)
        return results

    @rule('1.2')
    def _check_1_2_titles(self, root, namespaces, version):  # noqa
        """Checks that all major STIX constructs have a Title element.

        """
        to_check = (
            '{0}:Campaign'.format(common.PREFIX_STIX_CORE),
            '{0}:Campaign'.format(common.PREFIX_STIX_COMMON),
            '{0}:Course_Of_Action'.format(common.PREFIX_STIX_CORE),
            '{0}:Course_Of_Action'.format(common.PREFIX_STIX_COMMON),
            '{0}:Exploit_Target'.format(common.PREFIX_STIX_CORE),
            '{0}:Exploit_Target'.format(common.PREFIX_STIX_COMMON),
            '{0}:Incident'.format(common.PREFIX_STIX_CORE),
            '{0}:Incident'.format(common.PREFIX_STIX_COMMON),
            '{0}:Indicator'.format(common.PREFIX_STIX_CORE),
            '{0}:Indicator'.format(common.PREFIX_STIX_COMMON),
            '{0}:Threat_Actor'.format(common.PREFIX_STIX_COMMON),
            '{0}:Threat_Actor'.format(common.PREFIX_STIX_CORE),
            '{0}:TTP'.format(common.PREFIX_STIX_CORE),
            '{0}:TTP'.format(common.PREFIX_STIX_COMMON),
            '{0}:Report/{1}:Header'.format(common.PREFIX_STIX_CORE, common.PREFIX_STIX_REPORT),
            '{0}:Report/{1}:Header'.format(common.PREFIX_STIX_COMMON, common.PREFIX_STIX_REPORT)
        )

        results = self._check_titles(root, namespaces, to_check)
        return results

    @rule('1.0')
    def _check_marking_control_xpath(self, root, namespaces, version):  # noqa
        """Checks that data marking controlled structure XPaths are valid
        and resolve to nodes in the `root` document.

        """
        results = BestPracticeWarningCollection("Data Marking Control XPath")
        xpath = "//%s:Controlled_Structure" % common.PREFIX_DATA_MARKING

        for elem in root.xpath(xpath, namespaces=namespaces):
            if not elem.text:
                message = "Empty Control XPath"
            else:
                message = common.test_xpath(elem)

            if message:
                result = BestPracticeWarning(node=elem, message=message)
                results.append(result)

        return results

    @rule('1.0')
    def _check_condition_attribute(self, root, namespaces, version):  # noqa
        """Checks that Observable properties contain a ``@condition``
        attribute.

        This will also attempt to resolve Observables which are referenced
        (not embedded) within Indicators.

        Note:
            This could produce inaccurate results if a CybOX ObjectProperties
            instance contains fields that do not contain a ``condition``
            attribute (e.g., a field that is not patternable).

        """
        results = BestPracticeWarningCollection(
            "Indicator Pattern Properties Missing Condition Attributes"
        )

        selectors = (
            "//{0}:Indicator".format(common.PREFIX_STIX_CORE),
            "//{0}:Indicator".format(common.PREFIX_STIX_COMMON),
            "//{0}:Indicator".format(common.PREFIX_STIX_REPORT)
        )

        xpath = " | ".join(selectors)
        indicators = root.xpath(xpath, namespaces=namespaces)

        if len(indicators) == 0:
            return results

        def _get_leaves(nodes):
            """Finds and returns all leaf nodes contained within `nodes`."""
            leaves = []
            for n in nodes:
                leaves.extend(x for x in utils.leaves(n) if utils.has_content(x))
            return leaves

        def _get_observables(indicators):
            """Iterates over `indicators` and yields an (indicator instance,
            observable list) tuple with each pass.

            The observable list contains all observable instances embedded or
            referenced within the Indicator.

            """
            for indicator in indicators:
                observables = common.get_indicator_observables(
                    root=root,
                    indicator=indicator,
                    namespaces=namespaces
                )
                yield (indicator, observables)

        xpath = ".//{0}:Properties".format(common.PREFIX_CYBOX_CORE)
        for indicator, observables in _get_observables(indicators):
            id_ = indicator.attrib.get('id', 'No ID Found')

            for obs in observables:
                props = obs.xpath(xpath, namespaces=namespaces)

                for leaf in _get_leaves(props):
                    if leaf.attrib.get('condition'):
                        continue

                    result = BestPracticeWarning(leaf)
                    result['parent indicator id'] = id_
                    result['parent indicator line'] = indicator.sourceline
                    results.append(result)

        return results

    @rule('1.0')
    def _check_example_namespace(self, root, namespaces, version):  # noqa
        """Checks for nodes in the input `root` document that contain IDs
        which fall under the ``example`` namespace.

        """
        ex_namespaces = ('http://example.com', 'http://example.com/')

        # Get all the namespaces used in the document
        doc_nsmap = utils.get_document_namespaces(root)

        # Element tags to check for example ID presence
        to_check = itertools.chain(
            common.STIX_CORE_COMPONENTS,
            common.CYBOX_CORE_COMPONENTS
        )

        results = BestPracticeWarningCollection('IDs Use Example Namespace')
        xpath = " | ".join("//%s" % x for x in to_check)

        for node in root.xpath(xpath, namespaces=namespaces):
            if 'id' not in node.attrib:
                continue

            # ID attr found. Break it up into ns prefix and local parts
            id_parts = node.attrib['id'].split(":")

            if len(id_parts) != 2:
                continue

            # Try to get the namespace mapped to the ID ns prefix
            prefix = id_parts[0]
            ns = doc_nsmap.get(prefix)

            if ns not in ex_namespaces:
                continue

            result = BestPracticeWarning(node=node)
            results.append(result)

        return results

    def _get_1_2_tlo_deprecations(self, root, namespaces):
        """Checks for the existence of any idref elements inside the STIX
        Package top-level collections.

        """
        stix = (
            '//{0}:Campaigns/{0}:Campaign',
            '//{0}:Courses_Of_Action/{0}:Course_Of_Action',
            '//{0}:Exploit_Targets/{0}:Exploit_Target',
            '//{0}:Incidents/{0}:Incident',
            '//{0}:Indicators/{0}:Indicator',
            '//{0}:Threat_Actors/{0}:Threat_Actor',
            '//{0}:TTPs/{0}:TTP',
            '//{0}:Related_Packages/{0}:Related_Package/{0}:Package',
        )

        cybox = "//{0}:Observables/{1}:Observable".format(
            common.PREFIX_STIX_CORE,
            common.PREFIX_CYBOX_CORE
        )

        # Combine the STIX and CybOX selectors
        to_check = [x.format(common.PREFIX_STIX_CORE) for x in stix]
        to_check.append(cybox)

        xpath = " | ".join(to_check)
        nodes = root.xpath(xpath, namespaces=namespaces)

        # Create result collection
        msg = "IDREFs in top-level collections is deprecated."

        # Attach warnings to collection
        warns =  []
        for node in nodes:
            if 'idref' not in node.attrib:
                continue

            warn = BestPracticeWarning(node=node, message=msg)
            warns.append(warn)

        return warns

    def _get_1_2_related_package_deprecations(self, root, namespaces):
        """Checks for deprecated use of Related_Packages in STIX component
        instances.

        """
        selector = "//{0}:Related_Packages"
        prefixes = (
            common.PREFIX_STIX_CAMPAIGN,
            common.PREFIX_STIX_COA,
            common.PREFIX_STIX_EXPLOIT_TARGET,
            common.PREFIX_STIX_INCIDENT,
            common.PREFIX_STIX_INDICATOR,
            common.PREFIX_STIX_THREAT_ACTOR,
            common.PREFIX_STIX_TTP
        )

        to_check = (selector.format(prefix) for prefix in prefixes)
        xpath = " | ".join(to_check)
        nodes = root.xpath(xpath, namespaces=namespaces)

        msg = "Use of Related_Packages is deprecated."
        warns = [BestPracticeWarning(node=x, message=msg) for x in nodes]
        return warns

    def _get_1_2_package_deprecations(self, root, namespaces):
        """Checks for deprecated fields on STIX Package instances.

        """
        to_check = (
            "//{0}:STIX_Package".format(common.PREFIX_STIX_CORE),
            "//{0}:Package".format(common.PREFIX_STIX_CORE)
        )

        xpath = " | ".join(to_check)
        nodes = root.xpath(xpath, namespaces=namespaces)

        warns = []
        for node in nodes:
            attrib = node.attrib

            if 'idref' in attrib:
                msg = "@idref is deprecated in STIX Package."
                warn = BestPracticeWarning(node=node, message=msg)
                warns.append(warn)

            if 'timestamp' in attrib:
                msg = "@timestamp is deprecated in STIX Package."
                warn = BestPracticeWarning(node=node, message=msg)
                warns.append(warn)

        return warns

    def _get_1_2_header_warnings(self, root, namespaces):
        """Checks for deprecated fields on STIX Header instances.

        """
        to_check = (
            "{0}:Title".format(common.PREFIX_STIX_CORE),
            "{0}:Description".format(common.PREFIX_STIX_CORE),
            "{0}:Short_Description".format(common.PREFIX_STIX_CORE),
            "{0}:Package_Intent".format(common.PREFIX_STIX_CORE),
        )

        header = "//{0}:STIX_Header".format(common.PREFIX_STIX_CORE)
        xpath = " | ".join("%s/%s" % (header, x) for x in to_check)
        nodes = root.xpath(xpath, namespaces=namespaces)
        fmt = "%s is deprecated in STIX Header."

        warns = []
        for node in nodes:
            localname = utils.localname(node)
            msg = fmt % localname

            warn = BestPracticeWarning(node=node, message=msg)
            warns.append(warn)

        return warns

    @rule('1.2')
    def _check_1_2_deprecations(self, root, namespaces, version):  # noqa
        """Checks the input document `root` for fields that were deprecated
        in STIX v1.2.

        """
        package_warnings = self._get_1_2_package_deprecations(
            root=root,
            namespaces=namespaces
        )

        header_warnings = self._get_1_2_header_warnings(
            root=root,
            namespaces=namespaces
        )

        tlo_warnings = self._get_1_2_tlo_deprecations(
            root=root,
            namespaces=namespaces
        )

        related_package_warnings= self._get_1_2_related_package_deprecations(
            root=root,
            namespaces=namespaces
        )

        warns = itertools.chain(
            package_warnings,
            header_warnings,
            tlo_warnings,
            related_package_warnings
        )

        results = BestPracticeWarningCollection("STIX 1.2 Deprecations")
        results.extend(warns)

        return results

    def _get_campaign_related_indicators(self, root, namespaces):
        xpath = ".//{0}:Related_Indicators".format(common.PREFIX_STIX_CAMPAIGN)
        nodes = root.xpath(xpath, namespaces=namespaces)
        msg = "Related_Indicators has been deprecated in Campaign."
        return [BestPracticeWarning(node=n, message=msg) for n in nodes]


    @rule('1.1')
    def _check_1_1_deprecations(self, root, namespaces, version):  # noqa
        """Checks the input document `root` for fields that were deprecated
        in STIX v1.1.

        """
        results = BestPracticeWarningCollection("STIX 1.1 Deprecations")
        warns = self._get_campaign_related_indicators(root, namespaces)
        results.extend(warns)

        return results


    def _get_bad_ordinalities(self, nodes, tag, namespaces):
        """Returns a set of warnings for nodes in `nodes` that do not comply
        with @ordinality use of descriptive elements.

        Args:
            nodes: A set of nodes that have more than one instance of `tag`
                children.
            tag: The localname of the nodes to inspect for ordinalities.
            namespaces: A list of STIX namespaces.

        """
        def can_inspect(node):
            """Only check nodes that are in the STIX namespace and have a
            localname that matches the tag (e.g., 'Description').

            """
            qname = etree.QName(node)
            return (qname.localname == tag) and (qname.namespace in namespaces)


        filtered = []
        for node in nodes:
            # Filter out fields that belong to non-STIX namespaces
            filtered.extend(x for x in utils.iterchildren(node) if can_inspect(x))

        warns = []
        seen = set()

        for node in filtered:
            o = node.attrib.get('ordinality')

            if o is None:
                fmt = "@ordinality missing in '{0}' list."
                msg = fmt.format(tag)
                warns.append(BestPracticeWarning(node=node, message=msg))
                continue

            o = int(o)  # @ordinality is a xs:positiveInteger type.

            if o in seen:
                fmt = "@ordinality is duplicate in '{0}' list: '{1}'"
                msg = fmt.format(tag, o)
                warns.append(BestPracticeWarning(node=node, message=msg))
                continue

            seen.add(o)

        return warns

    @rule('1.2')
    def _check_structured_text_ordinalities(self, root, namespaces, version):  # noqa
        """Checks the input STIX document for correct ordinality usage in
        StructuredText lists.

        Checks for duplicates and missing ordinality attributes in elements
        that have lists of StructuredText instances.

        """

        # Selects nodes that have more than one instance of a specific
        # StructuredTextType child (i.e., more than one Description child).
        xpath_fmt = "//*[count(child::*[local-name()='{0}']) > 1]"

        tags = (
            "Description",
            "Short_Description",
            "Description_Of_Effect",
            "Business_Function_Or_Role"
        )

        title = "StructuredText @ordinality Use"
        results = BestPracticeWarningCollection(title)
        nslist = namespaces.values()

        for tag in tags:
            xpath = xpath_fmt.format(tag)
            nodes = root.xpath(xpath, namespaces=namespaces)

            if len(nodes) == 0:
                continue

            warns = self._get_bad_ordinalities(nodes, tag, nslist)
            results.extend(warns)

        return results

    def _get_rules(self, version):
        """Returns a list of best practice check functions that are applicable
        to the STIX `version`.

        """
        def can_run(stix_version, rule_min, rule_max):
            if not rule_min:
                return True

            doc_ver = parse_version(remove_version_prefix(stix_version))
            min_ver = parse_version(remove_version_prefix(rule_min))

            if rule_max:
                max_ver = parse_version(remove_version_prefix(rule_max))
                return (min_ver <= doc_ver <= max_ver)

            return min_ver <= doc_ver

        all_rules = self._rules.items()  # noqa

        # Get a generator which yields all best practice methods that are
        # assigned a version number <= the input STIX document version number.
        rules = []

        for (versions, funcs) in all_rules:
            min_, max_ = versions
            rules.extend(f for f in funcs if can_run(version, min_, max_))

        return rules

    def _run_rules(self, root, version):
        """Runs all best practice rules applicable to a `version` of STIX
        against the `root` document.

        """
        namespaces = common.get_stix_namespaces(version)
        results = BestPracticeValidationResults()
        rules = self._get_rules(version)

        for func in rules:
            result = func(self, root, namespaces=namespaces, version=version)
            results.append(result)

        return results

    @common.check_stix
    def validate(self, doc, version=None):
        """Checks that a STIX document aligns with `suggested authoring
        practices`_.

        .. _suggested authoring practices: http://stixproject.github.io/documentation/suggested-practices/

        Args:
            doc: The STIX document. Can be a filename, file-like object,
                lxml._Element, or lxml._ElementTree instance.
            version: The version of the STIX document. This will determine the
                set of best practice rules to check. If ``None`` an attempt
                will be made to extract the version from `doc`.

        Returns:
            An instance of
            :class:`.BestPracticeValidationResults`.

        Raises:
            .UnknownSTIXVersionError: If `version` was ``None`` and `doc`
                did not contain any version information.
            .InvalidSTIXVersionError: If discovered version or `version`
                argument contains an invalid STIX version number.
            .ValidationError: If there are any issues parsing `doc`.

        """
        # Get the element for the input document
        root = utils.get_etree_root(doc)

        # Get the STIX version for the input `doc` if one is not passed in.
        version = version or common.get_version(root)

        # Check that the version number is a valid STIX version number
        common.check_version(version)

        # Run the best practice checks applicable for the STIX version number.
        results = self._run_rules(root, version)

        # Return the results
        return results


__all__ = [
    'STIXBestPracticeValidator',
    'BestPracticeValidationResults',
    'BestPracticeWarningCollection',
    'BestPracticeWarning'
]
