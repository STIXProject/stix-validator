from sdv import ValidationError
import sdv.utils as utils

class UnknownVersionError(ValidationError):
    """Raised when no STIX version information can be found in an instance
    document and no version information was provided to a method which
    requires version information.

    """
    pass

class InvalidVersionError(ValidationError):
    """Raised when an invalid version of STIX is discovered within an instance
    document or is passed into a method which depends on STIX version
    information.

    Args:
        message: The error message.
        expected: A version or list of expected versions.
        found: The STIX version that was declared for an instance document or
            found within an instance document.

    """
    def __init__(self, message, expected=None, found=None):
        super(InvalidVersionError, self).__init__(message)
        self.expected = expected
        self.found = found

NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"

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

    """
    root = utils.get_etree_root(doc)
    return root.attrib['version']


def get_stix_namespaces(version):
    """Returns namespaces required to perform xpath evaluation on STIX
    documents.

    Returns:
        A dictionary mapping of namespace aliases to STIX namespaces.

    Raises:
        UnknownVersionError: If the `version` is ``None``.
        InvalidVersionError: If the `version` is not a valid version of STIX.

    """
    if not version:
        raise UnknownVersionError("Version cannot be None")

    if version not in STIX_VERSIONS:
         raise InvalidVersionError(
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