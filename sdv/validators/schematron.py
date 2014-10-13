# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from lxml import etree
from lxml import isoschematron
from collections import defaultdict

from sdv import ValidationResults
import sdv.utils as utils

NS_SVRL = "http://purl.oclc.org/dsdl/svrl"
NS_SCHEMATRON = "http://purl.oclc.org/dsdl/schematron"
NS_SAXON = "http://icl.com/saxon"   # libxml2 requires this namespace
NS_SAXON_SF_NET = "http://saxon.sf.net/"


class SchematronError(object):
    def __init__(self, doc, report, error):
        self._report = report
        self._doc = doc
        self._error = error

        self.message = self._parse_message(error)
        self._xpath_location = error.attrib.get('location')
        self._test = error.attrib.get('test')
        self._line = None

    def _get_line(self):
        root = utils.get_etree_root(self._doc)
        xpath = self._xpath_location
        nsmap = self._error.nsmap

        node = root.xpath(xpath, namespaces=nsmap)[0]
        return node.sourceline

    @property
    def line(self):
        if not self._line:
            self._line = self._get_line()

        return self._line


    def _parse_message(self, error):
        message = error.find("{%s}text" % NS_SVRL)

        if message == None:
            return None

        return message.text


    def __unicode__(self):
        return unicode(self.message)


    def __str__(self):
        return unicode(self).encode('utf-8')


class SchematronValidationResults(ValidationResults):
    """Used to hold results of a Schematron validation process.

    Args:
        report: An instance of :class:`SchematronReport`.

    Attributes:
        report: An instance of :class:`SchematronReport`

    """
    def __init__(self, doc, svrl_report):
        super(SchematronValidationResults, self).__init__()
        self._svrl_report = svrl_report
        self._doc = doc
        self.errors = self._parse_errors(svrl_report)


    def _parse_errors(self, report):
        xpath = "//svrl:failed-assert | //svrl:successful-report"
        nsmap = {'svrl': NS_SVRL}
        errors = report.xpath(xpath, namespaces=nsmap)

        return [SchematronError(self._doc, report, x) for x in errors]


    def as_dict(self):
        d = super(SchematronValidationResults, self).as_dict()

        if self.errors:
            errors = defaultdict(list)
            for error in self.errors:
                message = error.message
                lines = errors[message]
                lines.append(error.line)
                lines.sort()
                errors[error.message] = lines

            d['errors'] = dict(errors.items())

        return d


class SchematronValidator(object):
    def __init__(self, schematron):
        self.schematron = self._build_schematron(schematron)

    def _build_schematron(self, sch):
        if sch is None:
            raise ValueError("Input schematron document cannot be None")

        root = utils.get_etree_root(sch)
        schematron = isoschematron.Schematron(
            root, store_report=True, store_xslt=True, store_schematron=True
        )

        return schematron


    def get_xslt(self):
        """Returns an etree._ElementTree representation of the XSLT
        transform of the Schematron document.

        """
        return self.schematron.validator_xslt


    def get_schematron(self):
        """Returns an etree._ElementTree representation of the Schematron
        document.

        """
        return self.schematron.schematron


    def validate(self, doc):
        """Validates an XML instance document `doc` using Schematron rules.

        Returns:
            An instance of :class:`SchematronValidationResults`.

        """
        root = utils.get_etree_root(doc)
        is_valid = self.schematron.validate(root)
        svrl_report = self.schematron.validation_report

        results = SchematronValidationResults(root, svrl_report)
        results.is_valid = is_valid

        return results
            
