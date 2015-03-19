# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import re
import itertools
import collections
import distutils.version

# external
from lxml import etree

# internal
from sdv import utils, xmlconst

# relative
from . import common
from .. import base


# Python 2.6 doesn't have collections.OrderedDict :(
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict


def rule(version):
    """Decorator that identifies methods as being a STIX best practice checking
    rule.

    Args:
        version: Identifies the minimum version of STIX for which the decorated
            method applies.
    """
    def decorator(func):
        func.is_rule = True
        func.version = version
        return func
    return decorator


class BestPracticeMeta(type):
    """Metaclass that collects all :meth:`rule` decorated methods and
    builds an internal mapping of STIX version numbers to rules.

    """
    def __new__(metacls, name, bases, dict_):
        result = type.__new__(metacls, name, bases, dict_)

        result._rules = collections.defaultdict(list)  # pylint: disable=W0212
        rules = (x for x in dict_.itervalues() if hasattr(x, 'is_rule'))

        for rule in rules:
            result._rules[rule.version].append(rule)  # pylint: disable=W0212

        return result


class BestPracticeWarning(collections.MutableMapping, base.ValidationError):
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

        self._inner = OrderedDict()
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
        return tuple(x for x in self.iterkeys() if x not in self.core_keys)

    def as_dict(self):
        """Returns a dictionary representation of this class instance. This
        is implemented for consistency across other validation error types.

        The :class:`.BestPracticeWarning` class extends
        :class:`collections.MutableMapping`, so this method isn't really
        necessary.

        """
        return dict(self.iteritems())


class BestPracticeWarningCollection(collections.MutableSequence):
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


class BestPracticeValidationResults(base.ValidationResults, collections.MutableSequence):
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


class STIXBestPracticeValidator(object):
    """Performs STIX Best Practice validation."""

    __metaclass__ = BestPracticeMeta

    def __init__(self):
        pass

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
            if not any(x in node.attrib for x in ('id', 'idref')):
                warning = BestPracticeWarning(node=node)
                results.append(warning)

        return results

    @rule('1.0')
    def _check_id_format(self, root, namespaces, version):  # noqa
        """Checks that the core STIX/CybOX constructs in the STIX instance
        document have ids and that each id is formatted as follows:

        ``[ns_prefix]:[object-type]-[GUID].``

        """
        to_check = itertools.chain(
            common.STIX_CORE_COMPONENTS,
            common.CYBOX_CORE_COMPONENTS
        )

        regex = re.compile(r'\w+:\w+-')
        results = BestPracticeWarningCollection('ID Format')
        xpath = " | ".join("//%s" % x for x in to_check)

        for node in root.xpath(xpath, namespaces=namespaces):
            if 'id' not in node.attrib:
                continue

            id_ = node.attrib['id']
            if not regex.match(id_):
                result = BestPracticeWarning(node=node)
                results.append(result)

        return results

    @rule('1.0')
    def _check_duplicate_ids(self, root, namespaces, version):  # noqa
        """Checks for duplicate ids in the document.

        """
        id_nodes = collections.defaultdict(list)

        for node in root.xpath("//*[@id]"):
            id_nodes[node.attrib['id']].append(node)

        results = BestPracticeWarningCollection('Duplicate IDs')
        for nodes in id_nodes.itervalues():
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
        warnings = [
            BestPracticeWarning(x) for x in idrefs if idref(x) not in ids
        ]
        results.extend(warnings)

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
            return bool(node.text) or len(node.findall('*')) > 0

        nodes = root.xpath("//*[@idref]")
        warnings = [BestPracticeWarning(x) for x in nodes if is_invalid(x)]

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
            "{0}:Indicator".format(common.PREFIX_STIX_COMMON)
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

        for selector, expected in to_check.iteritems():
            xpath = "//%s" % selector

            for node in root.xpath(xpath, namespaces=namespaces):
                if _is_expected(node, expected):
                    continue

                warning = BestPracticeWarning(node)
                warning['version found'] = node.attrib['version']
                warning['version expected'] = expected
                results.append(warning)

        return results

    @rule('1.1')
    def _check_timestamp_usage(self, root, namespaces, **kwargs):  # noqa
        """Checks that all major STIX constructs have appropriate
        timestamp usage.

        Note:
            This does not check core CybOX constructs because they lack
            timestamp attributes.

        """
        results = BestPracticeWarningCollection("Timestamp Use")
        to_check = common.STIX_CORE_COMPONENTS
        xpath = " | ".join("//%s" % x for x in to_check)
        nodes = root.xpath(xpath, namespaces=namespaces)

        def _idref_resolves(idref, timestamp):
            xpath = "//*[@id='%s' and @timestamp='%s']" % (idref, timestamp)
            nodes = root.xpath(xpath, namespaces=namespaces)
            return all((nodes is not None, len(nodes) > 0))

        for node in nodes:
            attrib      = node.attrib.get
            id_         = attrib('id')
            idref       = attrib('idref')
            timestamp   = attrib('timestamp')
            warning     = None

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
                if _idref_resolves(idref, timestamp):
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

    @rule('1.0')
    def _check_titles(self, root, namespaces, version):  # noqa
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
            '{0}:TTP'.format(common.PREFIX_STIX_CORE),
            '{0}:TTP'.format(common.PREFIX_STIX_COMMON)
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

    @rule('1.0')
    def _check_marking_control_xpath(self, root, namespaces, version):  # noqa
        """Checks that data marking controlled structure XPaths are valid
        and resolve to nodes in the `root` document.

        """
        results = BestPracticeWarningCollection("Data Marking Control XPath")
        xpath = "//%s:Controlled_Structure" % common.PREFIX_DATA_MARKING

        def _test_xpath(node):
            """Checks that the xpath found on `node` meets the following
            requirements:

            * The xpath compiles (is a valid XPath)
            * The xpath selects at least one node in the document

            """
            try:
                xpath = node.text
                nodes = node.xpath(xpath, namespaces=root.nsmap)
                if len(nodes) == 0:
                    return "Control XPath does not return any results"
            except etree.XPathEvalError:
                return "Invalid XPath supplied"

        for elem in root.xpath(xpath, namespaces=namespaces):
            if not elem.text:
                message = "Empty Control XPath"
            else:
                message = _test_xpath(elem)

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
            "//{0}:Indicator".format(common.PREFIX_STIX_COMMON)
        )

        xpath = " | ".join(selectors)
        indicators = root.xpath(xpath, namespaces=namespaces)

        if len(indicators) == 0:
            return results

        def _get_leaves(nodes):
            """Finds and returns all leaf nodes contained within `nodes`."""
            leaves = []
            for node in nodes:
                leaves.extend(x for x in node.findall(".//*") if x.text)
            return leaves

        def _get_observables(indicators):
            """Iterates over `indicators` and yields an (indicator instance,
            observable list) tuple with each pass.

            The observable list contains all observable instances embedded or
            referenced within the Indicator.

            """
            for indicator in indicators:
                observables = common.get_indicator_observables(
                    root, indicator, namespaces
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

    def _get_rules(self, version):
        """Returns a list of best practice check functions that are applicable
        to the STIX `version`.

        """
        def is_applicable(func_version, stix_version):
            if not func_version:
                return True

            return StrictVersion(func_version) <= StrictVersion(stix_version)


        StrictVersion = distutils.version.StrictVersion
        checks = self._rules.iteritems()  # pylint: disable=E1101

        # Get a generator which yields all best practice methods that are
        # assigned a version number <= the input STIX document version number.
        rules = itertools.chain.from_iterable(
            funcs for (x, funcs) in checks if is_applicable(x, version)
        )

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

        .. _suggested authoring practices: http://common.roject.github.io/documentation/suggested-practices/

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
