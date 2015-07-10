# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import functools

# internal
from sdv import errors, utils


TAG_CYBOX_MAJOR  = "cybox_major_version"
TAG_CYBOX_MINOR  = "cybox_minor_version"
TAG_CYBOX_UPDATE = "cybox_update_version"

CYBOX_VERSIONS = ('2.0', '2.0.1', '2.1')


def get_version(doc):
    """Returns the version of the `observables` ``Observables`` node.

    Returns:
        A dotted-decimal a version string from the ``cybox_major``,
        ``cybox_minor`` and ``cybox_update`` attribute values.

    Raises:
        UnknownVersionError: If `observables` does not contain any of the
            following attributes:

            * ``cybox_major_version``
            * ``cybox_minor_version``
            * ``cybox_update_version``

    """
    observables  = utils.get_etree_root(doc)
    cybox_major  = observables.attrib.get(TAG_CYBOX_MAJOR)
    cybox_minor  = observables.attrib.get(TAG_CYBOX_MINOR)
    cybox_update = observables.attrib.get(TAG_CYBOX_UPDATE)

    if not any((cybox_major, cybox_minor, cybox_update)):
        error = "The input CybOX document has no version information."
        raise errors.UnknownCyboxVersionError(error)

    if cybox_update not in (None, '0'):
        version = "%s.%s.%s" % (cybox_major, cybox_minor, cybox_update)
    else:
        version = "%s.%s" % (cybox_major, cybox_minor)

    return version


def check_version(version):
    """Raises an exception if `version` is not a valid CybOX version.

    Args:
        version: A string CybOX version. Example: '2.1'

    Raises:
        .InvalidCyboxVersionError: If `version` is not a valid version of
            CybOX.

    """
    if version in CYBOX_VERSIONS:
        return

    raise errors.InvalidCyboxVersionError(
        message="Invalid CybOX version: '%s'" % version,
        expected=CYBOX_VERSIONS,
        found=version
    )


def check_root(doc):
    if utils.is_cybox(doc):
        return

    error = "Input document does not contain a valid CybOX root element."
    raise errors.ValidationError(error)


def check_cybox(func):
    """Decorator which checks that the input document is a CybOX document."""
    @functools.wraps(func)
    def inner(*args, **kwargs):
        try:
            doc = args[1]
        except IndexError:
            doc = kwargs['doc']

        # Get the root element for the input doc
        root = utils.get_etree_root(doc)

        # Check that the root is a valid CybOX root-level element
        check_root(root)

        return func(*args, **kwargs)

    return inner
