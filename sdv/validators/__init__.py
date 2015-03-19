# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# internal
from sdv import errors, utils

# relative
from .xml_schema import *  # noqa
from .schematron import *  # noqa
from .stix import *  # noqa
from .cybox import *  # noqa


def get_xml_validator_class(doc):
    """Returns the XML validator class required to validate the input
    `doc`.

    Args:
        doc: An XML document. This can be a filename, file-like object,
            ``etree._Element``, or ``etree._ElementTree`` instance.

    Returns:
        An XML Schema validator class (not object instance) which provides
        validation functionality required to validate `doc`.

    """
    root = utils.get_etree_root(doc)

    if utils.is_stix(root):
        return STIXSchemaValidator

    if utils.is_cybox(root):
        return CyboxSchemaValidator

    ns = utils.get_namespace(root)
    error = (
        "Unable determine validator class for input type. Root element "
        "namespace: {0}"
    ).format(ns)

    raise errors.ValidationError(error)
