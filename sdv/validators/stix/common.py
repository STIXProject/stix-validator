from sdv import ValidationError
import sdv.utils as utils

class UnknownVersionError(ValidationError):
    pass

class InvalidVersionError(ValidationError):
    def __init__(self, message, expected=None, found=None):
        super(InvalidVersionError, self).__init__(message)
        self.expected = expected
        self.found = found

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


def get_version(doc):
    root = utils.get_etree_root(doc)
    return root.attrib['version']


def get_stix_namespaces(version):
    if version in ('1.0', '1.0.1', '1.1', '1.1.1'):
        nsmap = {
            PREFIX_XSI: "http://www.w3.org/2001/XMLSchema-instance",
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
    else:
        raise UnknownVersionError(
            "Unable to determine namespaces for version '%s'" % version
        )

    return nsmap