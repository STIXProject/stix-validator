# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import os
import contextlib

# external
from lxml import etree
from distutils.version import StrictVersion

# relative
from . import errors, xmlconst

@contextlib.contextmanager
def ignored(*exceptions):
    """Allows you to ignore exceptions cleanly using context managers. This
    exists in Python 3.

    """
    try:
        yield
    except exceptions:
        pass


def get_xml_parser(encoding=None):
    """Returns an ``etree.ETCompatXMLParser`` instance."""
    parser = etree.ETCompatXMLParser(
        huge_tree=True,
        resolve_entities=False,
        remove_comments=False,
        strip_cdata=False,
        remove_blank_text=True,
        encoding=encoding
    )

    return parser


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


def list_xml_files(directory, recursive=False):
    """Returns a list of file paths for XML files contained within `dir_`.

    Args:
        dir_: A path to a directory.
        recursive: If ``True``, this function will descend into all
            subdirectories.

    Returns:
        A list of XML file paths directly under `dir_`.

    """
    files, dirs = [], []

    for fn in os.listdir(directory):
        fp = os.path.join(directory, fn)

        if fn.endswith('.xml'):
            files.append(fp)
        elif os.path.isdir(fp):
            dirs.append(fp)
        else:
            continue

    if recursive and dirs:
        files.extend(get_xml_files(dirs, recursive))

    return files


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
    if not files:
        return []

    xml_files = []
    for fn in files:
        if os.path.isdir(fn):
            children = list_xml_files(fn, recursive)
            xml_files.extend(children)
        else:
            xml_files.append(fn)

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
        raise errors.ValidationError(
            "xsi:type '%s' contains unresolvable namespace prefix." % typename
        )


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
    ``http://stix.mitre.org``, this will return True.

    """
    root = get_etree_root(doc)
    namespace = get_namespace(root)
    return namespace.startswith("http://stix.mitre.org")


def is_cybox(doc):
    """Attempts to determine if the input `doc` is a CybOX XML instance
    document. If the root-level element falls under a namespace which starts
    with ``http://cybox.mitre.org``, this will return True.

    """

    root = get_etree_root(doc)
    namespace = get_namespace(root)
    return namespace.startswith("http://cybox.mitre.org")


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