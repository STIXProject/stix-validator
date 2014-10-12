# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from lxml import etree
from lxml import isoschematron
from collections import defaultdict

from sdv import _BaseValidationResults
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

        if not message:
            return None

        return message.text


class SchematronReport(object):
    def __init__(self, doc, svrl_report):
        self._svrl_report = svrl_report
        self._doc = doc
        self.errors = self._parse_errors(svrl_report)

    def _parse_errors(self, report):
        '''Returns a list of SVRL failed-assert and successful-report elements.'''
        xpath = "//svrl:failed-assert | //svrl:successful-report"
        nsmap = {'svrl': NS_SVRL}
        errors = report.xpath(xpath, namespaces=nsmap)

        return [SchematronError(self._doc, report, x) for x in errors]

    def as_dict(self):
        d = defaultdict(list)
        for error in self.errors:
            message = error.message
            lines = d[message]
            lines.append(error.line)
            lines.sort()
            d[error.message] = lines

        return {'errors': d}


class SchematronValidationResults(_BaseValidationResults):
    def __init__(self, report):
        super(SchematronValidationResults, self).__init__()
        self.report = report

    @_BaseValidationResults.errors.setter
    def errors(self, value):
        pass

    @_BaseValidationResults.errors.getter
    def errors(self):
        return self.report.errors

    def as_dict(self):
        d = {}

        d['result'] = self.is_valid
        d.update(self.report.as_dict())

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
        return self.schematron.validator_xslt


    def get_schematron(self):
        self.schematron.schematron


    def validate(self, doc):
        root = utils.get_etree_root(doc)
        is_valid = self.schematron.validate(root)
        svrl_report = self.schematron.validation_report
        report = SchematronReport(root, svrl_report)

        results = SchematronValidationResults(report)
        results.is_valid = is_valid

        return results
            
