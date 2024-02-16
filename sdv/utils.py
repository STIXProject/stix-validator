# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import os
import contextlib
import datetime
from distutils.version import StrictVersion
from io import StringIO, BytesIO

# external
import dateutil.parser
from lxml import etree

# relative
from . import errors, xmlconst


_XML_PARSER = None


@contextlib.contextmanager
def ignored(*exceptions):
    """Allows you to ignore exceptions cleanly using context managers. This
    exists in Python 3.4 as ``contextlib.suppress()``.

    """
    try:
        yield
    except exceptions:
        pass


def get_xml_parser(encoding=None):
    """Returns the global XML parser object. If no global XML parser has
    been set, one will be created and then returned.

    Args:
        encoding: The expected encoding of input documents. By default, an
            attempt will be made to determine the input document encoding.

    Return:
        The global XML parser object.

    """
    global _XML_PARSER

    if not _XML_PARSER:
        _XML_PARSER = etree.ETCompatXMLParser(
            attribute_defaults=False,
            load_dtd=False,
            huge_tree=False,
            no_network=True,
            ns_clean=True,
            recover=False,
            remove_pis=False,
            remove_blank_text=False,
            remove_comments=False,
            resolve_entities=False,
            strip_cdata=True,
            encoding=encoding
        )

    return _XML_PARSER


def set_xml_parser(parser):
    """Set the XML parser to use internally. This should be an instance of
    ``lxml.etree.XMLParser``.

    Note:
        Setting `parser` to an object that is not an instance
        ``lxml.etree.XMLParser`` may result in undesired behaviors.

    Args:
        parser: An etree parser.

    """
    global _XML_PARSER
    _XML_PARSER = parser


def get_etree_root(doc):
    """Returns an instance of lxml.etree._Element for the given `doc` input.

    Args:
        doc: The input XML document. Can be an instance of
            ``lxml.etree._Element``, ``lxml.etree._ElementTree``, a file-like
            object, or a string filename.

    Returns:
        An ``lxml.etree._Element`` instance for `doc`.

    Raises:
        .ValidationError: If `doc` cannot be found or is not a well-formed
            XML document.

    """
    try:
        if isinstance(doc, etree._Element):  # noqa
            root = doc
        elif isinstance(doc, etree._ElementTree):  # noqa
            root = doc.getroot()
        else:
            parser = get_xml_parser()
            if isinstance(doc, StringIO):
                tree = etree.parse(BytesIO(doc.getvalue().encode()), parser=parser)
            else:
                tree = etree.parse(doc, parser=parser)
            root = tree.getroot()
    except Exception as ex:
        raise errors.ValidationError(str(ex))

    return root


def get_target_ns(doc):
    """Returns the value of the ``targetNamespace`` attribute found on `doc`.

    Returns:
        The value of the ``targetNamespace`` attribute found at the root of
        `doc`.

    Raises:
        KeyError: If `doc` does not contain a ``targetNamespace`` attribute.
        .ValidationError: If `doc` cannot be found or is not a well-formed
            XML document.

    """
    root = get_etree_root(doc)
    return root.attrib['targetNamespace']


def get_schemaloc_pairs(node):
    """Parses the xsi:schemaLocation attribute on `node`.

    Returns:
        A list of (ns, schemaLocation) tuples for the node.

    Raises:
        KeyError: If `node` does not have an xsi:schemaLocation attribute.

    """
    schemalocs = node.attrib[xmlconst.TAG_SCHEMALOCATION]
    l = schemalocs.split()
    pairs = zip(l[::2], l[1::2])

    return pairs


def is_xml(fn):
    """Returns ``True`` if the input filename `fn` ends with an XML extension.

    """
    return os.path.isfile(fn) and fn.lower().endswith('.xml')


def list_xml_files(directory, recursive=False):
    """Returns a list of file paths for XML files contained within `dir_`.

    Args:
        dir_: A path to a directory.
        recursive: If ``True``, this function will descend into all
            subdirectories.

    Returns:
        A list of XML file paths directly under `dir_`.

    """
    xml_files = []

    for top, _, files in os.walk(directory):
        # Get paths to each file in `files`
        paths = (os.path.join(top, f) for f in files)

        # Add all the .xml files to our return collection
        xml_files.extend(x for x in paths if is_xml(x))

        if not recursive:
            break

    return xml_files


def get_xml_files(files, recursive=False):
    """Returns a list of files to validate from `files`. If a member of `files`
    is a directory, its children with a ``.xml`` extension will be added to
    the return value.

    Args:
        files: A list of file paths and/or directory paths.
        recursive: If ``true``, this will descend into any subdirectories
            of input directories.

    Returns:
        A list of file paths to validate.

    """
    xml_files = []

    if not files:
        return xml_files

    for fn in files:
        if os.path.isdir(fn):
            children = list_xml_files(fn, recursive)
            xml_files.extend(children)
        elif is_xml(fn):
            xml_files.append(fn)
        else:
            continue

    return xml_files


def get_type_ns(doc, typename):
    """Returns the namespace associated with the ``xsi:type`` `typename`
    found in the XML document `doc`.

    Args:
        doc: An XML document. This can be a filename, file-like object,
            ``etree._Element``, or ``etree._ElementTree`` instance.
        typename: The ``xsi:type`` value for a given vocabulary instance.

    """
    root = get_etree_root(doc)
    prefix = typename.split(':')[0]

    try:
        return root.nsmap[prefix]
    except KeyError:
        msg = "xsi:type '%s' contains unresolvable namespace prefix." % typename
        raise errors.ValidationError(msg)


def get_namespace(node):
    """Returns the namespace for which `node` falls under.

    Args:
        node: An etree node.

    """
    qname = etree.QName(node)
    return qname.namespace


def is_stix(doc):
    """Attempts to determine if the input `doc` is a STIX XML instance document.
    If the root-level element falls under a namespace which starts with
    ``http://stix.mitre.org`` or ``http://docs.oasis-open.org/cti/ns/stix``,
    this will return True.

    """
    root = get_etree_root(doc)
    namespace = get_namespace(root)
    return (namespace.startswith("http://stix.mitre.org")
        or namespace.startswith("http://docs.oasis-open.org/cti/ns/stix"))


def is_cybox(doc):
    """Attempts to determine if the input `doc` is a CybOX XML instance
    document. If the root-level element falls under a namespace which starts
    with ``http://cybox.mitre.org`` or
    ``http://docs.oasis-open.org/cti/ns/cybox``, this will return True.

    """

    root = get_etree_root(doc)
    namespace = get_namespace(root)
    return (namespace.startswith("http://cybox.mitre.org")
        or namespace.startswith("http://docs.oasis-open.org/cti/ns/cybox"))


def is_version_equal(x, y):
    """Attempts to determine if the `x` amd `y` version numbers are semantically
    equivalent.

    Examples:
        The version strings "2.1.0" and "2.1" represent semantically equivalent
        versions, despite not being equal strings.

    Args:
        x: A string version number. Ex: '2.1.0'
        y: A string version number. Ex: '2.1'

    """
    return StrictVersion(x) == StrictVersion(y)


def parse_timestamp(value):
    """Attempts to parse `value` into an instance of ``datetime.datetime``. If
    `value` is ``None``, this function will return ``None``.

    Args:
        value: A timestamp. This can be a string or datetime.datetime value.

    """
    if not value:
        return None
    elif isinstance(value, datetime.datetime):
        return value
    return dateutil.parser.parse(value)


def has_tzinfo(timestamp):
    """Returns ``True`` if the `timestamp` includes timezone or UTC offset
    information.

    """
    ts = parse_timestamp(timestamp)
    return ts and bool(ts.tzinfo)


def strip_whitespace(string):
    """Returns a copy of `string` with all whitespace removed.

    """
    if string is None:
        return None

    return ''.join(string.split())


def is_leaf(node):
    """Returns ``True`` if `node` has no element children.

    """
    child = next(iterchildren(node), None)
    return child is None


def has_content(node):
    """Returns ``True`` if the `node` has children or text nodes.

    Note:
        This will ignore whitespace and XML comments.

    """
    if node is None:
        return False

    if not is_leaf(node):
        return True

    stripped = strip_whitespace(node.text)
    return bool(stripped)


def get_document_namespaces(doc):
    """Returns namespace dictionary for all the namespaces declared in the
    input `doc`.

    Args:
        doc: A read()-able XML document or etree node.

    """
    root = get_etree_root(doc)

    nsmap = {}
    for element in root.iter('*'):
        nsmap.update(element.nsmap)

    return nsmap


def localname(node):
    """Returns the localname for an etree Element `node`.

    """
    return etree.QName(node).localname


def namespace(node):
    """Returns the namespace for an etree Element `node`.

    """
    return etree.QName(node).namespace


def is_element(node):
    """Returns ``True`` if `node` is an etree._Element instance.

    """
    return isinstance(node, etree._Element)  # noqa


def is_equal_timestamp(ts1, ts2):
    """Returns ``True`` if the timestamps `ts1` and `ts2` are equal.

    Args:
        ts1: Timestamp string/datetime or etree Element node with 'timestamp'
            attribute.
        ts2: Timestamp string/datetime or etree Element node with 'timestamp'
            attribute.

    """
    if is_element(ts1):
        ts1 = ts1.attrib.get('timestamp')

    if is_element(ts2):
        ts2 = ts2.attrib.get('timestamp')

    try:
        return parse_timestamp(ts1) == parse_timestamp(ts2)
    except TypeError:
        # TypeError raised when comparing timestamps with and without
        # tzinfo. Return False in this case.
        return False


def iterchildren(node):
    """Returns an iterator which yields direct child elements of `node`.

    """
    return node.iterchildren('*')


def children(node):
    """Returns an iterable collection of etree Element nodes that are direct
    children of `node`.

    """
    return list(iterchildren(node))


def iterdescendants(node):
    """Returns an iterator which yields descendant elements of `node`.

    """
    return node.iterdescendants('*')


def descendants(node):
    """Returns a list of etree Element nodes that are descendants of `node`.

    """
    return list(iterdescendants(node))


def leaves(tree):
    """Returns an iterable collection of leaf nodes under `tree`.

    """
    xpath = ".//*[count(child::*) = 0]"
    return tree.xpath(xpath)


def remove_all(list_, items):
    """Removes all `items` from the `list_`.

    """
    for item in items:
        with ignored(ValueError):
            list_.remove(item)


def is_iterable(x):
    """Returns ``True`` if `x` is an iterable collection.

    Note:
        This will return ``False`` if `x` is a string type.

    """
    return hasattr(x, "__iter__")


def is_qname(string):
    """Returns ``True`` if `string` is a valid QName."""

    if ":" in string:
        prefix, _ = string.split(":", 1)
        xmlns = "xmlns:%s='http://example.com'" % prefix
    else:
        xmlns = ""

    try:
        xml = "<%s %s/>" % (string, xmlns)
        etree.XML(xml)
    except etree.XMLSyntaxError:
        return False

    return True


def union(selectors):
    """Returns a selector which is a union of the input selectors.

    Args:
        selectors: A list of XSLT/XPath selectors.

    Returns:
        A new selector string.
    """
    return " | ".join(x.strip() for x in selectors)

def remove_version_prefix(version):
    """Strips the 'stix-' prefix from a version number string so it can be
    compared with older version strings which do not have the prefix.

    """
    if version.startswith('stix-'):
        version = version.partition('stix-')[2]
    return version
