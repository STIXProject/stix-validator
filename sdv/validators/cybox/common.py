
# builtin
from distutils.version import StrictVersion

# internal
import sdv.errors as errors
import sdv.utils as utils


NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"

TAG_XSI_TYPE = "{%s}type" % NS_XSI
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
        raise errors.UnknownCyboxVersionError(
            "The input CybOX document has no version information."
        )

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
