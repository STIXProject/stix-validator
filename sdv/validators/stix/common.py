import sdv.errors as errors
import sdv.utils as utils

NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
TAG_XSI_TYPE = "{%s}type" % NS_XSI

PREFIX_XSI = 'xsi'
PREFIX_STIX_CORE = 'stix-core'
PREFIX_STIX_COMMON = 'stix-common'
PREFIX_STIX_CAMPAIGN = 'stix-campaign'
PREFIX_STIX_COA = 'stix-coa'
PREFIX_STIX_EXPLOIT_TARGET = 'stix-et'
PREFIX_STIX_INDICATOR = 'stix-indicator'
PREFIX_STIX_INCIDENT = 'stix-incident'
PREFIX_STIX_THREAT_ACTOR = 'stix-ta'
PREFIX_STIX_VOCABS = 'stix-vocabs'
PREFIX_DATA_MARKING = 'data-marking'
PREFIX_CYBOX_CORE = 'cybox-core'
PREFIX_CYBOX_COMMON = 'cybox-common'
PREFIX_CYBOX_VOCABS = 'cybox-vocabs'

STIX_VERSIONS = ('1.0', '1.0.1', '1.1', '1.1.1')

def get_version(doc):
    """Returns the version of a STIX instnace document.

    Args:
        doc: A STIX filename, file-like object, etree._Element or
            etree._ElementTree instance.

    Returns:
        The version of the document.

    Raises:
        KeyError: If the document does not contain a ``version`` attribute
            on the root node.
        .ValidationError: If there are any issues parsing `doc`.
    """
    root = utils.get_etree_root(doc)
    return root.attrib['version']


def check_version(version):
    """Raises an exception if `version` is not a valid STIX version.

    Args:
        version: A string STIX version. Example: '1.1.1'

    Raises:
        .InvalidSTIXVersionError: If `version` is not a valid version of
            STIX.

    """
    if version in STIX_VERSIONS:
        return

    raise errors.InvalidSTIXVersionError(
        message="Invalid STIX version: '%s'" % version,
        expected=STIX_VERSIONS,
        found=version
    )


def get_stix_namespaces(version):
    """Returns namespaces required to perform xpath evaluation on STIX
    documents.

    Returns:
        A dictionary mapping of namespace aliases to STIX namespaces.

    Raises:
        .UnknownSTIXVersionError: If the `version` is ``None``.
        .InvalidSTIXVersionError: If the `version` is not a valid version
            of STIX.

    """
    if not version:
        raise errors.UnknownSTIXVersionError("Version cannot be None")

    if version not in STIX_VERSIONS:
         raise errors.InvalidSTIXVersionError(
            "Unable to determine namespaces for version '%s'" % version,
            expected=STIX_VERSIONS,
            found=version
        )

    # At the moment, all STIX core-constructs have retained their namespaces
    # between revisions of STIX. There is no need to look up specific sets
    # of namespaces for a given version of STIX.
    nsmap = {
        PREFIX_XSI: NS_XSI,
        PREFIX_STIX_CORE: 'http://stix.mitre.org/stix-1',
        PREFIX_STIX_COMMON: 'http://stix.mitre.org/common-1',
        PREFIX_STIX_CAMPAIGN: 'http://stix.mitre.org/Campaign-1',
        PREFIX_STIX_COA: 'http://stix.mitre.org/CourseOfAction-1',
        PREFIX_STIX_EXPLOIT_TARGET: 'http://stix.mitre.org/ExploitTarget-1',
        PREFIX_STIX_INDICATOR: 'http://stix.mitre.org/Indicator-2',
        PREFIX_STIX_INCIDENT: 'http://stix.mitre.org/Incident-1',
        PREFIX_STIX_THREAT_ACTOR: 'http://stix.mitre.org/ThreatActor-1',
        PREFIX_STIX_VOCABS: 'http://stix.mitre.org/default_vocabularies-1',
        PREFIX_DATA_MARKING: 'http://data-marking.mitre.org/Marking-1',
        PREFIX_CYBOX_CORE: 'http://cybox.mitre.org/cybox-2',
        PREFIX_CYBOX_COMMON: 'http://cybox.mitre.org/common-2',
        PREFIX_CYBOX_VOCABS: 'http://cybox.mitre.org/default_vocabularies-2'
    }

    return nsmap