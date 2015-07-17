# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import collections

# external
import lxml.etree
import lxml.isoschematron

# internal
from sdv import utils, xmlconst

# relative
from .  import base


# SVRL error tags
ERROR_TAGS = (
    xmlconst.TAG_SVRL_FAILED_ASSERT,
    xmlconst.TAG_SVRL_SUCCESSFUL_REPORT
)


# Tuple for recording schematron validation errors.
# 'node" is the etree failed-assert or successful-report node.
# 'context' is the associated schematron rule context for the error.
SVRLError = collections.namedtuple(
    typename="SVRLError",
    field_names=["context", "node"]
)


def make_rule(ctx):
    """Returns a Schematron rule etree.Element for the given context."""
    name    = lxml.etree.QName(xmlconst.NS_SCHEMATRON, "rule")
    attrib  = {"context": ctx}
    nsmap   = {None: xmlconst.NS_SCHEMATRON}
    return lxml.etree.Element(name, attrib=attrib, nsmap=nsmap)


def make_pattern(id=None):
    """Returns a Schematron pattern etree.Element."""
    attrib = {}

    if id:
        attrib["id"] = id

    name = lxml.etree.QName(xmlconst.NS_SCHEMATRON, "pattern")
    nsmap = {None: xmlconst.NS_SCHEMATRON}
    return lxml.etree.Element(name, attrib=attrib, nsmap=nsmap)


def make_schema():
    """Returns a Schematron schema etree.Element."""
    name = lxml.etree.QName(xmlconst.NS_SCHEMATRON, "schema")
    nsmap = {None:xmlconst.NS_SCHEMATRON}
    return lxml.etree.Element(name, nsmap=nsmap)


def make_ns(prefix, uri):
    """Returns a Schematron ns etree.Element for the given ns prefix
    and uri.
    """
    name    = lxml.etree.QName(xmlconst.NS_SCHEMATRON, "ns")
    attrib  = {"prefix": prefix, "uri": uri}
    nsmap   = {None: xmlconst.NS_SCHEMATRON}
    return lxml.etree.Element(name, attrib=attrib, nsmap=nsmap)


class SchematronError(base.ValidationError):
    """Represents an error found in a SVRL report.

    Args:
        doc: The instance document which was validated and produced this error.
        error: The ``svrl:failed-assert`` or ``svrl:successful-report``
            ``etree._Element`` instance.

    Attributes:
        message: The validation error message.

    """
    def __init__(self, doc, error):
        super(SchematronError, self).__init__()
        node = error.node

        self._doc = doc
        self._error = node
        self._xpath_location = node.attrib.get('location')
        self._test = node.attrib.get('test')
        self._line = None
        self.context = error.context
        self.message = self._parse_message(node)

    def __unicode__(self):
        return unicode(self.message)

    def __str__(self):
        return unicode(self).encode("utf-8")

    def _get_line(self):
        """Returns the line number in the input document associated with this
        error.

        """
        root = utils.get_etree_root(self._doc)
        xpath = self._xpath_location
        nsmap = self._error.nsmap

        node = root.xpath(xpath, namespaces=nsmap)[0]
        return node.sourceline

    @property
    def line(self):
        """Returns the line number in the input document associated with this
        error.

        This property is lazily evaluated, meaning the line number isn't known
        until the first time this property is accessed. Each subsequent call
        will return the cached line number.

        """
        if not self._line:
            self._line = self._get_line()

        return self._line

    def _parse_message(self, error):
        message = error.find("{%s}text" % xmlconst.NS_SVRL)

        if message is None:
            return ""

        return message.text

    def as_dict(self):
        """Returns a dictionary representation.

        Keys:
            * ``'message'``: The error message
            * ``'line'``: The line number associated with the error
        """
        return dict(message=self.message, line=self.line)


class SchematronValidationResults(base.ValidationResults):
    """Used to hold results of a Schematron validation process.

    Args:
        is_valid: The boolean validation result.
        doc: The document which produced these validation results.
        svrl_report: The etree._ElementTree SVRL report produced during the
            validation run.

    Attributes:
        errors: A list of :class:`SchematronError` instances representing
            errors found in the `svrl_report`.
        is_valid: Returns ``True`` if the validation was successful and
            ``False`` otherwise.

    """
    def __init__(self, is_valid, doc=None, svrl_report=None):
        super(SchematronValidationResults, self).__init__(is_valid)
        self._svrl_report = svrl_report
        self._doc = doc
        self.errors = self._parse_errors(svrl_report)

    def _get_errors(self, svrl_report):
        """Parses errors from the SVRL report document.

        Args:
            svrl_report: An etree SVRL document.

        Returns:
            A list of :class:`SVRLError` objects.
        """
        errors = []

        if not svrl_report:
            return errors

        root = svrl_report.getroot()

        for element in utils.descendants(root):
            if element.tag == xmlconst.TAG_SVRL_FIRED_RULE:
                context = element.attrib['context']
                continue

            if element.tag not in ERROR_TAGS:
                continue

            error = SVRLError(context=context, node=element)
            errors.append(error)

        return errors

    def _parse_errors(self, svrl_report):
        errors = self._get_errors(svrl_report)
        return [SchematronError(self._doc, x) for x in errors]

    def as_dict(self):
        """A dictionary representation of the
        :class:`.SchematronValidationResults` instance.

        Keys:
            * ``'result'``: The validation results. Values can be
              ``True`` or ``False``.
            * ``'errors'``: A list of validation error dictionaries. The keys
              are ``'message'`` and ``'line'``.

        Returns:
            A dictionary representation of an instance of this class.

        """
        d = super(SchematronValidationResults, self).as_dict()

        if self.errors:
            d['errors'] = [x.as_dict() for x in self.errors]

        return d


class SchematronValidator(object):
    """Performs schematron validation against an XML instance document.

    Args:
        schematron: A Schematron document. This can be a filename, file-like
            object, ``etree._Element``, or ``etree._ElementTree`` instance.

    """

    def __init__(self, schematron, phase=None):
        self._schematron = self._build_schematron(schematron, phase)
        self._phase_id = phase

    def _build_schematron(self, sch, phase=None):
        """Attempts to build an ``lxml.isoschematron.Schematron`` instance
        from `sch`.

        Args:
            sch: A Schematron document filename, file-like object,
                etree._Element, or etree._ElementTree.

        Returns:
            A ``lxml.isoschematron.Schematron`` instance for `sch`.

        """
        if sch is None:
            raise ValueError("Input schematron document cannot be None")

        root = utils.get_etree_root(sch)
        schematron = lxml.isoschematron.Schematron(
            root,
            phase=phase,
            store_report=True,
            store_xslt=True,
            store_schematron=True
        )

        return schematron

    @property
    def xslt(self):
        """Returns an etree._ElementTree representation of the XSLT
        transform of the Schematron document.

        """
        return self._schematron.validator_xslt

    @property
    def schematron(self):
        """Returns an etree._ElementTree representation of the Schematron
        document.

        """
        return self._schematron.schematron

    def validate(self, doc):
        """Validates an XML instance document `doc` using Schematron rules.

        Args:
            doc: An XML instance document. This can be a filename, file-like
                object, ``etree._Element`` or ``etree._ElementTree`` instance.

        Returns:
            An instance of
            :class:`.SchematronValidationResults`.

        Raises:
              .ValidationError: If there are any issues parsing `doc`.

        """
        root = utils.get_etree_root(doc)
        is_valid = self._schematron.validate(root)
        svrl_report = self._schematron.validation_report

        return SchematronValidationResults(
            is_valid=is_valid,
            doc=root,
            svrl_report=svrl_report
        )


__all__ = [
    'SchematronValidator',
    'SchematronValidationResults',
    'SchematronError'
]
