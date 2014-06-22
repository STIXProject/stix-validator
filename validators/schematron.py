# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from lxml import etree
from lxml import isoschematron
from collections import defaultdict

class SchematronValidator(object):
    NS_SVRL = "http://purl.oclc.org/dsdl/svrl"
    NS_SCHEMATRON = "http://purl.oclc.org/dsdl/schematron"
    NS_SAXON = "http://icl.com/saxon" # libxml2 requires this namespace instead of http://saxon.sf.net/
    NS_SAXON_SF_NET = "http://saxon.sf.net/"
    
    def __init__(self, schematron=None):
        self.schematron = None # isoschematron.Schematron instance
        self._init_schematron(schematron)
        
    def _init_schematron(self, schematron):
        '''Returns an instance of lxml.isoschematron.Schematron'''
        if schematron is None:
            self.schematron = None
            return
        elif not (isinstance(schematron, etree._Element) or isinstance(schematron, etree._ElementTree)):
            parser = etree.ETCompatXMLParser(huge_tree=True)
            tree = etree.parse(schematron, parser=parser)
        else:
            tree = schematron
            
        self.schematron = isoschematron.Schematron(tree, store_report=True, store_xslt=True, store_schematron=True)
        
    def get_xslt(self):
        if not self.schematron:
            return None
        return self.schematron.validator_xslt
      
    def get_schematron(self):
        if not self.schematron:
            return None 
        return self.schematron.schematron
    
    def _build_result_dict(self, result, report=None):
        '''Creates a dictionary to be returned by the validate() method.'''
        d = {}
        d['result'] = result
        if report:
                d['report'] = report
        return d
    
    def _get_schematron_errors(self, validation_report):
        '''Returns a list of SVRL failed-assert and successful-report elements.'''
        xpath = "//svrl:failed-assert | //svrl:successful-report"
        errors = validation_report.xpath(xpath, namespaces={'svrl':self.NS_SVRL})
        return errors
    
    def _get_error_line_numbers(self, d_error, tree):
        '''Returns a sorted list of line numbers for a given Schematron error.'''
        locations = d_error['locations']
        nsmap = d_error['nsmap']
        
        line_numbers = []
        for location in locations:
            ctx_node = tree.xpath(location, namespaces=nsmap)[0]
            if ctx_node.sourceline not in line_numbers: 
                line_numbers.append(ctx_node.sourceline)
        
        line_numbers.sort()
        return line_numbers
    
    def _build_error_dict(self, errors, instance_tree, report_line_numbers=True):
        '''Returns a dictionary representation of the SVRL validation report:
        d0 = { <Schemtron error message> : d1 }
        
        d1 = { "locations" : A list of XPaths to context nodes,
               "line_numbers" : A list of line numbers where the error occurred,
               "test" : The Schematron evaluation expression used,
               "text" : The Schematron error message }
        
        '''
        d_errors = {}
        
        for error in errors:
            text = error.find("{%s}text" % self.NS_SVRL).text
            location = error.attrib.get('location')
            test = error.attrib.get('test') 
            if text in d_errors:
                d_errors[text]['locations'].append(location)
            else:
                d_errors[text] = {'locations':[location], 'test':test, 'nsmap':error.nsmap, 'text':text}
        
        if report_line_numbers:
            for d_error in d_errors.itervalues():
                line_numbers = self._get_error_line_numbers(d_error, instance_tree)
                d_error['line_numbers'] = line_numbers
        
        return d_errors
    
    def _build_error_report_dict(self, validation_report, instance_tree, report_line_numbers=True): 
        errors = self._get_schematron_errors(validation_report)
        d_errors = self._build_error_dict(errors, instance_tree, report_line_numbers)
        report_dict = defaultdict(list)
        for msg, d in d_errors.iteritems():
            d_error = {'error' : msg}
            if 'line_numbers' in d:
                d_error['line_numbers'] = d['line_numbers']
            report_dict['errors'].append(d_error)
            
        return report_dict
    
    def validate(self, instance, report_line_numbers=True):
        '''Validates an XML instance document.
        
        Arguments:
        report_line_numbers : Includes error line numbers in the returned dictionary.
                              This may slow performance.
                              
        '''
        if not self.schematron:
            raise Exception('Schematron document not set. Cannot validate. Call init_schematron(...) and retry.')
        try:
            if isinstance(instance, etree._Element):
                tree = etree.ElementTree(instance)
            elif isinstance(instance, etree._ElementTree):
                tree = instance
            else:
                parser = etree.ETCompatXMLParser(huge_tree=True)
                tree = etree.parse(instance, parser=parser)
            
            result = self.schematron.validate(tree)
            report = self._build_error_report_dict(self.schematron.validation_report, tree, report_line_numbers)

            if len(report['errors']) > 0:
                report = self._build_error_report_dict(self.schematron.validation_report, tree, report_line_numbers)
                return self._build_result_dict(result, report)
            else:
                return self._build_result_dict(result)
            
        except etree.ParseError as e:
            return self._build_result_dict(False, [str(e)])    