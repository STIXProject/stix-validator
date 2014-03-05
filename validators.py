# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import os
import re
from collections import defaultdict
from lxml import etree
from lxml import isoschematron
import xlrd

class XmlValidator(object):
    NS_XML_SCHEMA_INSTANCE = "http://www.w3.org/2001/XMLSchema-instance"
    NS_XML_SCHEMA = "http://www.w3.org/2001/XMLSchema"
    
    def __init__(self, schema_dir=None, use_schemaloc=False):
        self.__imports = self._build_imports(schema_dir)
        self.__use_schemaloc = use_schemaloc
    
    def _get_target_ns(self, fp):
        '''Returns the target namespace for a schema file
        
        Keyword Arguments
        fp - the path to the schema file
        '''
        tree = etree.parse(fp)
        root = tree.getroot()
        return root.attrib['targetNamespace'] # throw an error if it doesn't exist...we can't validate
        
    def _get_include_base_schema(self, list_schemas):
        '''Returns the root schema which defines a namespace.
        
        Certain schemas, such as OASIS CIQ use xs:include statements in their schemas, where two schemas
        define a namespace (e.g., XAL.xsd and XAL-types.xsd). This makes validation difficult, when we
        must refer to one schema for a given namespace.
        
        To fix this, we attempt to find the root schema which includes the others. We do this by seeing
        if a schema has an xs:include element, and if it does we assume that it is the parent. This is
        totally wrong and needs to be fixed. Ideally this would build a tree of includes and return the
        root node.
        
        Keyword Arguments:
        list_schemas - a list of schema file paths that all belong to the same namespace
        '''
        parent_schema = None
        tag_include = "{%s}include" % (self.NS_XML_SCHEMA)
        
        for fn in list_schemas:
            tree = etree.parse(fn)
            root = tree.getroot()
            includes = root.findall(tag_include)
            
            if len(includes) > 0: # this is a hack that assumes if the schema includes others, it is the base schema for the namespace
                return fn
                
        return parent_schema
    
    def _build_imports(self, schema_dir):
        '''Given a directory of schemas, this builds a dictionary of schemas that need to be imported
        under a wrapper schema in order to enable validation. This returns a dictionary of the form
        {namespace : path to schema}.
        
        Keyword Arguments
        schema_dir - a directory of schema files
        '''
        if not schema_dir:
            return None
        
        imports = defaultdict(list)
        for top, dirs, files in os.walk(schema_dir):
            for f in files:
                if f.endswith('.xsd'):
                    fp = os.path.join(top, f)
                    target_ns = self._get_target_ns(fp)
                    imports[target_ns].append(fp)
        
        for k,v in imports.iteritems():
            if len(v) > 1:
                base_schema = self._get_include_base_schema(v)
                imports[k] = base_schema
            else:
                imports[k] = v[0]
    
        return imports
    
    def _build_wrapper_schema(self, import_dict):
        '''Creates a wrapper schema that imports all namespaces defined by the input dictionary. This enables
        validation of instance documents that refer to multiple namespaces and schemas
        
        Keyword Arguments
        import_dict - a dictionary of the form {namespace : path to schema} that will be used to build the list of xs:import statements
        '''
        schema_txt = '''<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="http://stix.mitre.org/tools/validator" elementFormDefault="qualified" attributeFormDefault="qualified"/>'''
        root = etree.fromstring(schema_txt)
        
        tag_import = "{%s}import" % (self.NS_XML_SCHEMA)
        for ns, list_schemaloc in import_dict.iteritems():
            schemaloc = list_schemaloc
            schemaloc = schemaloc.replace("\\", "/")
            attrib = {'namespace' : ns, 'schemaLocation' : schemaloc}
            el_import = etree.Element(tag_import, attrib=attrib)
            root.append(el_import)
    
        return root

    def _extract_schema_locations(self, root):
        schemaloc_dict = {}
        
        tag_schemaloc = "{%s}schemaLocation" % (self.NS_XML_SCHEMA_INSTANCE)
        schemaloc = root.attrib[tag_schemaloc].split()
        schemaloc_pairs = zip(schemaloc[::2], schemaloc[1::2])
        
        for ns, loc in schemaloc_pairs:
            schemaloc_dict[ns] = loc
        
        return schemaloc_dict
    
    def _build_result_dict(self, result, errors=None):
        d = {}
        d['result'] = result
        d['errors'] = errors
        return d
    
    def validate(self, instance_doc):
        '''Validates an instance documents.
        
        Returns a tuple of where the first item is the boolean validation
        result and the second is the validation error if there was one.
        
        Keyword Arguments
        instance_doc - a filename, file-like object, etree._Element, or etree._ElementTree to be validated
        '''
        if not(self.__use_schemaloc or self.__imports):
            return (False, "No schemas to validate against! Try instantiating XmlValidator with use_schemaloc=True or setting the schema_dir")
        
        if isinstance(instance_doc, etree._Element):
            instance_root = instance_doc
        elif isinstance(instance_doc, etree._ElementTree):
            instance_root = instance_doc.getroot()
        else:
            try:
                et = etree.parse(instance_doc)
                instance_root = et.getroot()
            except etree.XMLSyntaxError as e:
                return self._build_result_dict(False, str(e))
            
        if self.__use_schemaloc:
            try:
                required_imports = self._extract_schema_locations(instance_root)
            except KeyError as e:
                return (False, "No schemaLocation attribute set on instance document. Unable to validate")
        else:
            required_imports = {}
            for prefix, ns in instance_root.nsmap.iteritems():
                schemaloc = self.__imports.get(ns)
                if schemaloc:
                    required_imports[ns] = schemaloc

        if not required_imports:
            return (False, "Unable to determine schemas to validate against")

        wrapper_schema_doc = self._build_wrapper_schema(import_dict=required_imports)
        xmlschema = etree.XMLSchema(wrapper_schema_doc)
        
        try: 
            xmlschema.assertValid(instance_root)
            return self._build_result_dict(True)
        except Exception as e:
            return self._build_result_dict(False, str(e))


class STIXValidator(XmlValidator):
    '''Schema validates STIX v1.0.1 documents and checks best practice guidance'''
    __stix_version__ = "1.0.1"
    
    PREFIX_STIX_CORE = 'stix'
    PREFIX_CYBOX_CORE = 'cybox'
    PREFIX_STIX_INDICATOR = 'indicator'
    
    NS_STIX_CORE = "http://stix.mitre.org/stix-1"
    NS_STIX_INDICATOR = "http://stix.mitre.org/Indicator-2"
    NS_CYBOX_CORE = "http://cybox.mitre.org/cybox-2"
    
    NS_MAP = {PREFIX_CYBOX_CORE : NS_CYBOX_CORE,
              PREFIX_STIX_CORE : NS_STIX_CORE,
              PREFIX_STIX_INDICATOR : NS_STIX_INDICATOR}
    
    def __init__(self, schema_dir=None, use_schemaloc=False, best_practices=False):
        super(STIXValidator, self).__init__(schema_dir, use_schemaloc)
        self.best_practices = best_practices
        
    def _check_id_presence_and_format(self, instance_doc):
        '''Checks that the core STIX/CybOX constructs in the STIX instance document
        have ids and that each id is formatted as [ns_prefix]:[object-type]-[GUID].
        
        Returns a dictionary of lists. Each dictionary has the following keys:
        no_id - a list of etree Element objects for all nodes without ids
        format - a list of etree Element objects with ids not formatted as [ns_prefix]:[object-type]-[GUID]
    
        Keyword Arguments
        instance_doc - an etree Element object for a STIX instance document
        '''
        return_dict = {'no_id' : [],
                       'format' : []}
        
        elements_to_check = ['stix:Campaign',
                             'stix:Course_Of_Action',
                             'stix:Exploit_Target',
                             'stix:Incident',
                             'stix:Indicator',
                             'stix:STIX_Package',
                             'stix:Threat_Actor',
                             'stix:TTP',
                             'cybox:Observable',
                             'cybox:Object',
                             'cybox:Event',
                             'cybox:Action']
    
        for tag in elements_to_check:
            xpath = ".//%s" % (tag)
            elements = instance_doc.xpath(xpath, namespaces=self.NS_MAP)
            
            for e in elements:
                try:
                    if not re.match(r'\w+:\w+-', e.attrib['id']): # not the best regex
                        return_dict['format'].append({'tag':e.tag, 'id':e.attrib['id'], 'line_number':e.sourceline})
                except KeyError as ex:
                    return_dict['no_id'].append({'tag':e.tag, 'line_number':e.sourceline})
            
        return return_dict
    
    def _check_duplicate_ids(self, instance_doc):
        '''Looks for duplicate ids in a STIX instance document. 
        
        Returns a dictionary of lists. Each dictionary uses the offending
        id as a key, which points to a list of etree Element nodes which
        use that id.
        
        Keyword Arguments
        instance_doc - an etree.Element object for a STIX instance document
        '''
        dict_id_nodes = defaultdict(list)
        dup_dict = {}
        xpath_all_nodes_with_ids = "//*[@id]"
        
        all_nodes_with_ids = instance_doc.xpath(xpath_all_nodes_with_ids)
        for node in all_nodes_with_ids:
            dict_id_nodes[node.attrib['id']].append(node)
        
        for id,node_list in dict_id_nodes.iteritems():
            if len(node_list) > 1:
                dup_dict[id] = [{'tag':node.tag, 'line_number':node.sourceline} for node in node_list]
        
        return dup_dict
    
    def _check_idref_resolution(self, instance_doc):
        '''Checks that all idref attributes in the input document resolve to a local element.
        Returns a list etree.Element nodes with unresolveable idrefs.
        
        Keyword Arguments
        instance_doc - an etree.Element object for a STIX instance document
        '''
        list_unresolved_ids = []
        xpath_all_idrefs = "//*[@idref]"
        xpath_all_ids = "//@id"
        
        all_idrefs = instance_doc.xpath(xpath_all_idrefs)
        all_ids = instance_doc.xpath(xpath_all_ids)
        
        for node in all_idrefs:
            if node.attrib['idref'] not in all_ids:
                d = {'tag': node.tag,
                     'idref': node.attrib['idref'],
                     'line_number' : node.sourceline}
                list_unresolved_ids.append(d)
                
        return list_unresolved_ids
                
    def _check_idref_with_content(self, instance_doc):
        '''Looks for elements that have an idref attribute set, but also have content.
        Returns a list of etree.Element nodes.
        
        Keyword Arguments:
        instance_doc - an etree.Element object for a STIX instance document
        '''
        list_nodes = []
        xpath = "//*[@idref]"
        nodes = instance_doc.xpath(xpath)
        
        for node in nodes:
            if node.text or len(node) > 0:
                d = {'tag' : node.tag,
                     'idref' : node.attrib['idref'],
                     'line_number' : node.sourceline}
                list_nodes.append(node)
                
        return list_nodes
    
    def _check_indicator_practices(self, instance_doc):
        '''Looks for STIX Indicators that are missing a Title, Description, Type, Valid_Time_Position, 
        Indicated_TTP, and/or Confidence
        
        Returns a list of dictionaries. Each dictionary has the following keys:
        id - the id of the indicator
        node - the etree.Element object for the indicator
        missing - a list of constructs missing from the indicator
        
        Keyword Arguments
        instance_doc - etree Element for a STIX sinstance document
        '''
        list_indicators = []
        xpath = "//%s:Indicator | %s:Indicator" % (self.PREFIX_STIX_CORE, self.PREFIX_STIX_INDICATOR)
        
        nodes = instance_doc.xpath(xpath, namespaces=self.NS_MAP)
        for node in nodes:
            dict_indicator = defaultdict(list)
            if not node.attrib.get('idref'): # if this is not an idref node, look at its content
                if node.find('{%s}Title' % (self.NS_STIX_INDICATOR)) is None:
                    dict_indicator['missing'].append('Title')
                if node.find('{%s}Description' % (self.NS_STIX_INDICATOR)) is None:
                    dict_indicator['missing'].append('Description')
                if node.find('{%s}Type' % (self.NS_STIX_INDICATOR)) is None:
                    dict_indicator['missing'].append('Type')
                if node.find('{%s}Valid_Time_Position' % (self.NS_STIX_INDICATOR)) is None:
                    dict_indicator['missing'].append('Valid_Time_Position')
                if node.find('{%s}Indicated_TTP' % (self.NS_STIX_INDICATOR)) is None:
                    dict_indicator['missing'].append('TTP')
                if node.find('{%s}Confidence' % (self.NS_STIX_INDICATOR)) is None:
                    dict_indicator['missing'].append('Confidence')
                
                if dict_indicator:
                    dict_indicator['id'] = node.attrib.get('id')
                    dict_indicator['line_number'] = node.sourceline
                    list_indicators.append(dict_indicator)
                
        return list_indicators
 
    def _check_root_element(self, instance_doc):
        d = {}
        if instance_doc.tag != "{%s}STIX_Package" % (self.NS_STIX_CORE):
            d['tag'] = instance_doc.tag
            d['line_number'] = instance_doc.sourceline
        return d
            
 
    def check_best_practices(self, instance_doc):
        '''Checks that a STIX instance document is following best practice guidance.
        
        Looks for the following:
        + idrefs that do not resolve locally
        + elements with duplicate ids
        + elements without ids
        + elements with ids not formatted as [ns_prefix]:[object-type]-[GUID]
        + indicators missing a Title, Description, Type, Valid_Time_Position, Indicated_TTP, and/or Confidence
        
        Returns a dictionary of lists and other dictionaries. This is maybe not ideal but workable.
        
        Keyword Arguments
        instance_doc - a filename, file-like object, etree._Element or etree.ElementTree for a STIX instance document
        '''
        
        if isinstance(instance_doc, etree._Element):
            root = instance_doc
        elif isinstance(instance_doc, etree._ElementTree):
            root = instance_doc.getroot()
        elif isinstance(instance_doc, basestring):
            tree = etree.parse(instance_doc)
            root = tree.getroot()
        else:
            instance_doc.seek(0)
            tree = etree.parse(instance_doc)
            root = tree.getroot()
        
        root_element = self._check_root_element(root)
        list_unresolved_idrefs = self._check_idref_resolution(root)
        dict_duplicate_ids = self._check_duplicate_ids(root)
        dict_presence_and_format = self._check_id_presence_and_format(root)
        list_idref_with_content = self._check_idref_with_content(root)
        list_indicators = self._check_indicator_practices(root)
        
        d = {}
        if root_element:
            d['root_element'] = root_element
        if list_unresolved_idrefs:
            d['unresolved_idrefs'] = list_unresolved_idrefs
        if dict_duplicate_ids:
            d['duplicate_ids'] = dict_duplicate_ids
        if dict_presence_and_format:
            if dict_presence_and_format.get('no_id'):
                d['missing_ids'] = dict_presence_and_format['no_id']
            if dict_presence_and_format.get('format'):
                d['id_format'] = dict_presence_and_format['format']
        if list_idref_with_content:
            d['idref_with_content'] = list_idref_with_content
        if list_indicators:
            d['indicator_suggestions'] = list_indicators
        
        return d
    
    def validate(self, instance_doc):
        '''Validates a STIX document and checks best practice guidance if STIXValidator
        was initialized with best_practices=True.
        
        Best practices will not be checked if the document is schema-invalid.
        
        Keyword Arguments
        instance_doc - a filename, file-like object, etree._Element or etree.ElementTree for a STIX instance document
        '''
        result_dict = super(STIXValidator, self).validate(instance_doc)
        
        isvalid = result_dict['result']
        if self.best_practices and isvalid:
            best_practice_warnings = self.check_best_practices(instance_doc)
        else:
            best_practice_warnings = None
        
        if best_practice_warnings:
            result_dict['best_practice_warnings'] = best_practice_warnings
             
        return result_dict

class SchematronValidator(object):
    NS_SVRL = "http://purl.oclc.org/dsdl/svrl"
    NS_SCHEMATRON = "http://purl.oclc.org/dsdl/schematron"
    
    def __init__(self, schematron=None):
        self.schematron = None # isoschematron.Schematron instance
        self.init_schematron(schematron)
        
    def init_schematron(self, schematron):
        '''Returns an instance of lxml.isoschematron.Schematron'''
        if schematron is None:
            self.schematron = None
            return
        elif not (isinstance(schematron, etree._Element) or isinstance(schematron, etree._ElementTree)):
            tree = etree.parse(schematron)
        else:
            tree = schematron
            
        self.schematron = isoschematron.Schematron(tree, store_report=True, store_xslt=True, store_schematron=True)
    
    def _element_to_file(self, tree, fn):    
        with open(fn, "wb") as f:
            f.write(etree.tostring(tree, pretty_print=True))
    
    def _build_result_dict(self, result, report=None):
        d = {}
        d['result'] = result
        if 'error' in report:
            d['errors'] = report['error']
        if 'warning' in report:
            d['warnings'] = report['warning']
        
        return d
    
    def _build_error_report_dict(self, validation_report):
        errors = isoschematron.svrl_validation_errors(validation_report)
        report_dict = defaultdict(list)
        
        for error in errors:
            role = error.attrib['role']
            text_node = error.find("{%s}text" % self.NS_SVRL)
            report_dict[role].append(text_node.text)
        
        return report_dict
    
    def validate(self, instance):
        if not self.schematron:
            raise Exception('Schematron document not set. Cannot validate. Call init_schematron(...) and retry.')
        try:
            if isinstance(instance, etree._Element):
                tree = etree.ElementTree(instance)
            elif isinstance(instance, etree._ElementTree):
                tree = instance
            else:
                tree = etree.parse(instance)
            
            result = self.schematron.validate(tree)
            if not result:
                report = self._build_error_report_dict(self.schematron.validation_report)
                return self._build_result_dict(result, report)
            else:
                return self._build_result_dict(result)
            
        except etree.ParseError as e:
            return self._build_result_dict(False, [str(e)])    

class ProfileValidator(SchematronValidator):
    def __init__(self, profile_fn):
        profile = self._open_profile(profile_fn)
        schema = self._parse_profile(profile) # schematron schema etree
        super(ProfileValidator, self).__init__(schematron=schema)
        
    def _build_rule_dict(self, worksheet):
        d = defaultdict(list)
        for i in range(1, worksheet.nrows):
            if self._get_cell_value(worksheet, i, 2) != "":
                field = self._get_cell_value(worksheet, i, 0)
                context = self._get_cell_value(worksheet, i, 1)
                occurrence = self._get_cell_value(worksheet, i, 2)
                xsi_type = self._get_cell_value(worksheet, i, 3)
                allowed_value = self._get_cell_value(worksheet, i, 4)
                
                if occurrence == "required":
                    text = "%s required for this STIX profile. " % field
                    if xsi_type:
                        text += "The allowed xsi:type is: '%s'. " % xsi_type
                    if allowed_value:
                        text += "The only allowed value is '%s'. " % allowed_value
                elif occurrence == "optional":
                    text = "%s is optional for this STIX profile." % field
                elif occurrence == "prohibited":
                    text = "%s is prohibited for this STIX profile." % field
                else:
                    raise Exception("Found unknown 'occurence' value: %s. Aborting." % occurrence)
                
                d[context].append({'field' : field,
                                   'text' : text.strip(),
                                   'occurrence' : occurrence,
                                   'xsi_type' : xsi_type,
                                   'allowed_value' : allowed_value})
        return d
    
    def _build_schematron_xml(self, rules, nsmap):
        root = etree.Element("{%s}schema" % self.NS_SCHEMATRON, nsmap={None:self.NS_SCHEMATRON})
        pattern = self._add_element(root, "pattern", id="STIX_Schematron_Profile")
        
        for context, tests in rules.iteritems():
            rule_element = self._add_element(pattern, "rule", context=context)
            for test in tests:
                test_element = self._add_element(node=rule_element, name="assert", text=test['text'])
                self._cell_to_node(test_element, test)
        
        self._map_ns(root, nsmap) # add namespaces to the schematron document
        return root
    
    def _parse_namespace_worksheet(self, worksheet):
        nsmap = {}
        for i in range(1, worksheet.nrows): # skip the first row
            ns = self._get_cell_value(worksheet, i, 0)
            alias = self._get_cell_value(worksheet, i, 1)
            nsmap[ns] = alias
        return nsmap      
    
    def _parse_profile(self, profile):
        overview_worksheet = profile.sheet_by_name("Overview")
        namespace_worksheet = profile.sheet_by_name("Namespaces")
                
        all_rules = defaultdict(list)
        for worksheet in profile.sheets():
            if worksheet.name not in ("Overview", "Namespaces"):
                rules = self._build_rule_dict(worksheet)
                for context,d in rules.iteritems():
                    all_rules[context].extend(d)

        namespaces = self._parse_namespace_worksheet(namespace_worksheet)
        schema = self._build_schematron_xml(all_rules, namespaces)
        
        self._unload_workbook(profile)
        return schema
        
    def _cell_to_node(self, node, d):
        field = d['field']
        occurrence = d['occurrence']
        allowed_value = d['allowed_value']
        xsi_type = d['xsi_type']
        
        if occurrence == "required":
            node.set("role", "error")
            node.set("test", field)
        elif occurrence == "prohibited":
            node.set("role", "error")
            node.set("test", "not(%s)" % field)
        else:
            node.set("role", "warning")
            node.set("test", field)
        
        if allowed_value:
            test_str = "%s='%s'" % (field, allowed_value)
            node.set("test", test_str)
        
        if xsi_type:
            test_str = "//%s[@xsi:type='%s']" % (field, xsi_type)
            node.set("test", test_str)
            
    def _map_ns(self, schematron, nsmap):
        for ns, prefix in nsmap.iteritems():
            ns_element = etree.Element("{%s}ns" % self.NS_SCHEMATRON)
            ns_element.set("prefix", prefix)
            ns_element.set("uri", ns)
            schematron.insert(0, ns_element)
            
    def _add_element(self, node, name, text=None, **kwargs):
        child = etree.SubElement(node, "{%s}%s" % (self.NS_SCHEMATRON, name))
        if text:
            child.text = text
        for k,v in kwargs.iteritems():
            child.set(k, v)
        return child
    
    def _unload_workbook(self, workbook):
        for worksheet in workbook.sheets():
            workbook.unload_sheet(worksheet.name)
            
    def _get_cell_value(self, worksheet, row, col):
        if not worksheet:
            raise Exception("worksheet value was NoneType")
        value = str(worksheet.cell_value(row, col))
        return value
    
    def _convert_to_string(self, value):
        if isinstance(value, unicode):
            return value.encode("UTF-8")
        else:
            return str(value)
    
    def _open_profile(self, filename):
        if not filename.lower().endswith(".xlsx"):
            raise Exception("File must have .XLSX extension. Filename provided: %s" % filename)
        try:
            return xlrd.open_workbook(filename)
        except:
            raise Exception("File does not seem to be valid XLSX.")
    
    def _get_schema_copy(self):
        copy = etree.ElementTree(self.schema)
        return copy.getroot()
    
    def validate(self, instance_doc):
        return super(ProfileValidator, self).validate(instance_doc)
