import os
import contextlib
from lxml import etree
import sdv.errors as errors

NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
TAG_XSI_TYPE = "{%s}type" % NS_XSI
TAG_SCHEMALOCATION = "{%s}schemaLocation" % NS_XSI


@contextlib.contextmanager
def ignored(*exceptions):
    """Allows you to ignore exceptions cleanly using context managers. This
    exists in Python 3.

    """
    try:
        yield
    except exceptions:
        pass


def get_xml_parser():
    """Returns an ``etree.ETCompatXMLParser`` instance."""
    parser = etree.ETCompatXMLParser(
        huge_tree=True,
        resolve_entities=False,
        remove_comments=False,
        strip_cdata=False,
        remove_blank_text=True
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
        if isinstance(doc, etree._Element):
            root = doc
        elif isinstance(doc, etree._ElementTree):
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
    schemalocs = node.attrib[TAG_SCHEMALOCATION]
    l = schemalocs.split()
    pairs = zip(l[::2], l[1::2])

    return pairs


def list_xml_files(dir_, recursive=False):
    """Returns a list of file paths for XML files contained within `dir_`.

    Args:
        dir_: A path to a directory.
        recursive: If ``True``, this function will descend into all
            subdirectories.

    Returns:
        A list of XML file paths directly under `dir_`.

    """
    files, dirs = [], []

    for fn in os.listdir(dir_):
        fp = os.path.join(dir_, fn)

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
