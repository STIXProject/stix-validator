# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import re
import functools
from distutils.version import StrictVersion

# external
from lxml import etree

# internal
import sdv.errors as errors
import sdv.utils as utils
import sdv.xmlconst as xmlconst

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
PREFIX_DATA_MARKING = 'stix-marking'
PREFIX_CYBOX_CORE = 'cybox-core'
PREFIX_CYBOX_COMMON = 'cybox-common'
PREFIX_CYBOX_VOCABS = 'cybox-vocabs'

STIX_VERSIONS = ('1.0', '1.0.1', '1.1', '1.1.1')

STIX_TO_CYBOX_VERSIONS = {
    '1.0': '2.0',
    '1.0.1': '2.0.1',
    '1.1': '2.1',
    '1.1.1': '2.1'
}

STIX_COMPONENT_VERSIONS = {
    '1.0': {
        '{0}:STIX_Package'.format(PREFIX_STIX_CORE): '1.0',
        '{0}:Campaign'.format(PREFIX_STIX_CORE): '1.0',
        '{0}:Campaign'.format(PREFIX_STIX_COMMON): '1.0',
        '{0}:Course_Of_Action'.format(PREFIX_STIX_CORE): '1.0',
        '{0}:Course_Of_Action'.format(PREFIX_STIX_COMMON): '1.0',
        '{0}:Exploit_Target'.format(PREFIX_STIX_CORE): '1.0',
        '{0}:Exploit_Target'.format(PREFIX_STIX_COMMON): '1.0',
        '{0}:Incident'.format(PREFIX_STIX_CORE): '1.0',
        '{0}:Incident'.format(PREFIX_STIX_COMMON): '1.0',
        '{0}:Indicator'.format(PREFIX_STIX_CORE): '2.0',
        '{0}:Indicator'.format(PREFIX_STIX_COMMON): '2.0',
        '{0}:Threat_Actor'.format(PREFIX_STIX_COMMON): '1.0',
        '{0}:Threat_Actor'.format(PREFIX_STIX_CORE): '1.0',
        '{0}:TTP'.format(PREFIX_STIX_CORE): '1.0',
        '{0}:TTP'.format(PREFIX_STIX_COMMON): '1.0'
    },
    '1.0.1': {
        '{0}:STIX_Package'.format(PREFIX_STIX_CORE): '1.0.1',
        '{0}:Campaign'.format(PREFIX_STIX_CORE): '1.0.1',
        '{0}:Campaign'.format(PREFIX_STIX_COMMON): '1.0.1',
        '{0}:Course_Of_Action'.format(PREFIX_STIX_CORE): '1.0.1',
        '{0}:Course_Of_Action'.format(PREFIX_STIX_COMMON): '1.0.1',
        '{0}:Exploit_Target'.format(PREFIX_STIX_CORE): '1.0.1',
        '{0}:Exploit_Target'.format(PREFIX_STIX_COMMON): '1.0.1',
        '{0}:Incident'.format(PREFIX_STIX_CORE): '1.0.1',
        '{0}:Incident'.format(PREFIX_STIX_COMMON): '1.0.1',
        '{0}:Indicator'.format(PREFIX_STIX_CORE): '2.0.1',
        '{0}:Indicator'.format(PREFIX_STIX_COMMON): '2.0.1',
        '{0}:Threat_Actor'.format(PREFIX_STIX_COMMON): '1.0.1',
        '{0}:Threat_Actor'.format(PREFIX_STIX_CORE): '1.0.1',
        '{0}:TTP'.format(PREFIX_STIX_CORE): '1.0.1',
        '{0}:TTP'.format(PREFIX_STIX_COMMON): '1.0.1'
    },
    '1.1': {
        '{0}:STIX_Package'.format(PREFIX_STIX_CORE): '1.1',
        '{0}:Campaign'.format(PREFIX_STIX_CORE): '1.1',
        '{0}:Campaign'.format(PREFIX_STIX_COMMON): '1.1',
        '{0}:Course_Of_Action'.format(PREFIX_STIX_CORE): '1.1',
        '{0}:Course_Of_Action'.format(PREFIX_STIX_COMMON): '1.1',
        '{0}:Exploit_Target'.format(PREFIX_STIX_CORE): '1.1',
        '{0}:Exploit_Target'.format(PREFIX_STIX_COMMON): '1.1',
        '{0}:Incident'.format(PREFIX_STIX_CORE): '1.1',
        '{0}:Incident'.format(PREFIX_STIX_COMMON): '1.1',
        '{0}:Indicator'.format(PREFIX_STIX_CORE): '2.1',
        '{0}:Indicator'.format(PREFIX_STIX_COMMON): '2.1',
        '{0}:Threat_Actor'.format(PREFIX_STIX_COMMON): '1.1',
        '{0}:Threat_Actor'.format(PREFIX_STIX_CORE): '1.1',
        '{0}:TTP'.format(PREFIX_STIX_CORE): '1.1',
        '{0}:TTP'.format(PREFIX_STIX_COMMON): '1.1'
    },
    '1.1.1': {
        '{0}:STIX_Package'.format(PREFIX_STIX_CORE): '1.1.1',
        '{0}:Campaign'.format(PREFIX_STIX_CORE): '1.1.1',
        '{0}:Campaign'.format(PREFIX_STIX_COMMON): '1.1.1',
        '{0}:Course_Of_Action'.format(PREFIX_STIX_CORE): '1.1.1',
        '{0}:Course_Of_Action'.format(PREFIX_STIX_COMMON): '1.1.1',
        '{0}:Exploit_Target'.format(PREFIX_STIX_CORE): '1.1.1',
        '{0}:Exploit_Target'.format(PREFIX_STIX_COMMON): '1.1.1',
        '{0}:Incident'.format(PREFIX_STIX_CORE): '1.1.1',
        '{0}:Incident'.format(PREFIX_STIX_COMMON): '1.1.1',
        '{0}:Indicator'.format(PREFIX_STIX_CORE): '2.1.1',
        '{0}:Indicator'.format(PREFIX_STIX_COMMON): '2.1.1',
        '{0}:Threat_Actor'.format(PREFIX_STIX_COMMON): '1.1.1',
        '{0}:Threat_Actor'.format(PREFIX_STIX_CORE): '1.1.1',
        '{0}:TTP'.format(PREFIX_STIX_CORE): '1.1.1',
        '{0}:TTP'.format(PREFIX_STIX_COMMON): '1.1.1'
    },
}

STIX_CORE_COMPONENTS = (
    '{0}:STIX_Package'.format(PREFIX_STIX_CORE),
    '{0}:Campaign'.format(PREFIX_STIX_CORE),
    '{0}:Campaign'.format(PREFIX_STIX_COMMON),
    '{0}:Course_Of_Action'.format(PREFIX_STIX_CORE),
    '{0}:Course_Of_Action'.format(PREFIX_STIX_COMMON),
    '{0}:Exploit_Target'.format(PREFIX_STIX_CORE),
    '{0}:Exploit_Target'.format(PREFIX_STIX_COMMON),
    '{0}:Incident'.format(PREFIX_STIX_CORE),
    '{0}:Incident'.format(PREFIX_STIX_COMMON),
    '{0}:Indicator'.format(PREFIX_STIX_CORE),
    '{0}:Indicator'.format(PREFIX_STIX_COMMON),
    '{0}:Threat_Actor'.format(PREFIX_STIX_CORE),
    '{0}:Threat_Actor'.format(PREFIX_STIX_COMMON),
    '{0}:TTP'.format(PREFIX_STIX_CORE),
    '{0}:TTP'.format(PREFIX_STIX_COMMON)
)

CYBOX_CORE_COMPONENTS = (
    '{0}:Observables'.format(PREFIX_CYBOX_CORE),
    '{0}:Observable'.format(PREFIX_CYBOX_CORE),
    '{0}:Object'.format(PREFIX_CYBOX_CORE),
    '{0}:Event'.format(PREFIX_CYBOX_CORE),
    '{0}:Action'.format(PREFIX_CYBOX_CORE)
)

STIX_VOCAB_VERSIONS = {
    '1.0': {
        'PackageIntentVocab': '1.0',
        'HighMediumLowVocab': '1.0',
        'MalwareTypeVocab': '1.0',
        'IndicatorTypeVocab': '1.0',
        'COAStageVocab': '1.0',
        'CampaignStatusVocab': '1.0',
        'IncidentStatusVocab': '1.0',
        'SecurityCompromiseVocab': '1.0',
        'DiscoveryMethodVocab': '1.0',
        'AvailabilityLossTypeVocab': '1.0',
        'LossDurationVocab': '1.0',
        'OwnershipClassVocab': '1.0',
        'ManagementClassVocab': '1.0',
        'LocationClassVocab': '1.0',
        'ImpactQualificationVocab': '1.0',
        'ImpactRatingVocab': '1.0',
        'AssetTypeVocab': '1.0',
        'AttackerInfrastructureTypeVocab': '1.0',
        'SystemTypeVocab': '1.0',
        'InformationTypeVocab': '1.0',
        'ThreatActorTypeVocab': '1.0',
        'MotivationVocab': '1.0',
        'IntendedEffectVocab': '1.0',
        'PlanningAndOperationalSupportVocab': '1.0',
        'IncidentEffectVocab': '1.0',
        'AttackerToolTypeVocab': '1.0',
        'IncidentCategoryVocab': '1.0',
        'LossPropertyVocab': '1.0',
    },
    '1.0.1': {
        'MotivationVocab': '1.0.1',
        'PlanningAndOperationalSupportVocab': '1.0.1',
    },
    '1.1': {
        'IndicatorTypeVocab': '1.1',
        'MotivationVocab': '1.1',
        'CourseOfActionTypeVocab': '1.0',
        'ThreatActorSophisticationVocab': '1.0',
        'InformationSourceRoleVocab': '1.0',
    },
    '1.1.1': {
        'AvailabilityLossTypeVocab': '1.1.1',
    }
}

CYBOX_VOCAB_VERSIONS = {
    '2.0': {
        'ActionArgumentNameVocab': '1.0',
        'ActionObjectAssociationTypeVocab': '1.0',
        'ActionNameVocab': '1.0',
        'ActionRelationshipTypeVocab': '1.0',
        'ActionTypeVocab': '1.0',
        'CharacterEncodingVocab': '1.0',
        'EventTypeVocab': '1.0',
        'HashNameVocab': '1.0',
        'InformationSourceTypeVocab': '1.0',
        'ObjectRelationshipVocab': '1.0',
        'ObjectStateVocab': '1.0',
        'ToolTypeVocab': '1.0'
    },
    '2.0.1': {
        'EventTypeVocab': '1.0.1'
    },
    '2.1': {
        'ActionNameVocab': '1.1',
        'ObjectRelationshipVocab': '1.1',
        'ToolTypeVocab': '1.1',
    }
}


def is_idref_content_exception(node):
    """Returns ``True`` if the `node` is an exception to the rule that
    nodes containing an ``idref`` attribute should not contain content.

    Note:
        This function will need to be updated in the future to be STIX/CybOX
        version-aware.

    """
    qname = etree.QName(node)
    return all((
        qname.localname == "Related_Object",
        qname.namespace == "http://cybox.mitre.org/cybox-2"
    ))


def _get_cybox_vocab_version(name, version):
    descending = reversed(
        sorted(CYBOX_VOCAB_VERSIONS.keys(), key=lambda x: StrictVersion(x))
    )
    keys = tuple(descending)
    idx = keys.index

    for key in keys[idx(version):]:
        vocabs = CYBOX_VOCAB_VERSIONS[key]

        if name in vocabs:
            return vocabs[name]

    raise errors.UnknownVocabularyError(
        "Unknown controlled vocabulary name: '%s'" % name
    )


def _get_stix_vocab_version(name, version):
    descending = reversed(
        sorted(STIX_VOCAB_VERSIONS.keys(), key=lambda x: StrictVersion(x))
    )
    keys = tuple(descending)
    idx = keys.index

    for key in keys[idx(version):]:
        vocabs = STIX_VOCAB_VERSIONS[key]

        if name in vocabs:
            return vocabs[name]

    raise errors.UnknownVocabularyError(
        "Unknown controlled vocabulary name: '%s'" % name
    )


def get_vocab_version(doc, version, typename):
    """Returns the version of a controlled vocabulary ``xsi:type`` expected for
    a given `version` of STIX or CybOX content.

    Note:
        This will need to be refactored in the future to support multiple
        STIX and CybOX default vocabulary namespaces.

    Args:
        doc: The XML document which contains the controlled vocabulary
            instance.
        version: A version of STIX.
        typename: The ``xsi:type`` for the controlled vocabulary instance.

    """
    namespace = utils.get_type_ns(doc, typename)
    name = parse_vocab_name(typename)

    if namespace == 'http://cybox.mitre.org/default_vocabularies-2':
        cybox_version = STIX_TO_CYBOX_VERSIONS[version]
        return _get_cybox_vocab_version(name, cybox_version)

    if namespace == 'http://stix.mitre.org/default_vocabularies-1':
        return _get_stix_vocab_version(name, version)

    raise errors.UnknownNamespaceError(
        "Unknown vocabulary namespace: '%s'" % namespace
    )


def parse_vocab_name(typename):
    """Parses a controlled vocabulary name from an instance ``xsi:type``
    value.

    Args:
        typename: The ``xsi:type`` value found on a controlled vocabulary
            instance.

    Returns:
        The name portion of a controlled vocabulary type instance. For example,
        given ``vocabs:IndicatorTypeVocab-1.0``, this would return
        ``'IndicatorTypeVocab'``.

    """
    type_ = re.split(":|-", typename)
    return type_[1]


def parse_vocab_version(typename):
    """Parses a controlled vocabulary version from an instance ``xsi:type``
    value.

    Args:
        typename: The ``xsi:type`` value found on a controlled vocabulary
            instance.

    Returns:
        The version portion of a controlled vocabulary type instance. For
        example, given ``vocabs:IndicatorTypeVocab-1.0``, this would return
        ``'1.0'``.

    """
    type_ = re.split(":|-", typename)
    return type_[2]


def get_version(doc):
    """Returns the version of a STIX instnace document.

    Args:
        doc: A STIX filename, file-like object, etree._Element or
            etree._ElementTree instance.

    Returns:
        The version of the document.

    Raises:
        .UnknownSTIXVersionError: If the document does not contain a
            ``version`` attribute on the root node.
        .ValidationError: If there are any issues parsing `doc`.
    """
    root = utils.get_etree_root(doc)

    try:
        return root.attrib['version']
    except KeyError:
        error = "Document did not contain a 'version' attribute"
        raise errors.UnknownSTIXVersionError(error)


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
        PREFIX_XSI: xmlconst.NS_XSI,
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


def _get_observable(root, obs, namespaces):
    """Attempts to return the Observable definition for `obs`. If `obs` is a
    fully defined (not idref'd) Observable, this function will immediately
    return `obs`.

    If `obs` contains an ``idref`` attribute, an attempt will be made to
    resolve the Observable definition. If the attempt fails, `obs` will be
    returned.

    Raises:
        .IdrefLookupError: if the attempt to resolve an idref fails.

    """
    idref = obs.attrib.get('idref')

    if not idref:
        return obs

    xpath = "//{0}:Observable[@id='{1}']".format(PREFIX_CYBOX_CORE, idref)
    nodes = root.xpath(xpath, namespaces=namespaces)

    if len(nodes) != 0:
        return nodes[0]

    raise errors.IdrefLookupError(
        idref=idref,
        message="Failed to resolve idref '{0}'".format(idref)
    )


def get_indicator_observables(root, indicator, namespaces):
    """Returns all Observable instances embedded or referenced within the
    `indicator`.

    Args:
        root: The etree STIX document.
        indicator: A STIX Indicator etree instance.
        namespaces: A mapping of namespace aliases to namespaces to be used
            by the XPath engine.

    Returns:
        A list of Observable instances.

    """
    xpath = ".//{0}:Observable".format(PREFIX_STIX_INDICATOR)

    observables = []
    for node in indicator.xpath(xpath, namespaces=namespaces):
        with utils.ignored(errors.IdrefLookupError):
            obs = _get_observable(root, node, namespaces)
            observables.append(obs)

    return observables


def check_root(doc):
    if utils.is_stix(doc):
        return

    error = "Input document does not contain a valid STIX root element."
    raise errors.ValidationError(error)


def check_stix(func):
    """Decorator which checks that the input document is a STIX document."""

    @functools.wraps(func)
    def _check_stix(*args, **kwargs):
        try:
            doc = args[1]
        except IndexError:
            doc = kwargs['doc']

        # Get the root element for the input doc
        root = utils.get_etree_root(doc)

        # Check that the root is a valid STIX root-level element
        check_root(root)

        return func(*args, **kwargs)

    return _check_stix