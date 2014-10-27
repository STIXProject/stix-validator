import os
import sdv.errors as errors
from lxml import etree

NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
TAG_XSI_TYPE = "{%s}type" % NS_XSI
TAG_SCHEMALOCATION = "{%s}schemaLocation" % NS_XSI

def get_xml_parser():
    """Returns an ``etree.ETCompatXMLParser`` instance."""

    parser = etree.ETCompatXMLParser(
        huge_tree=True,
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
        IOError: If `doc` is an invalid filename or file-like object

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


def list_xml_files(dir_):
    """Returns a list of file paths for XML files contained within `dir_`.

    Args:
        dir_: A path to a directory

    Returns:
        A list of XML file paths directly under `dir_`.

    """
    xml = []
    for fn in os.listdir(dir_):
        if fn.endswith('.xml'):
            fp = os.path.join(dir_, fn)
            xml.append(fp)

    return xml


def get_xml_files(files):
    """Returns a list of files to validate from `files`. If a member of `files`
    is a directory, its children with a ``.xml`` extension will be added to
    the return value.

    Args:
        A list of file paths and/or directory paths.

    Returns:
        A list of file paths to validate.

    """
    if not files:
        return []

    xml = []
    for fn in files:
        if os.path.isdir(fn):
            children = list_xml_files(fn)
            xml.extend(children)
        else:
            xml.append(fn)

    return xml
