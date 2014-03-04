#!/usr/bin/env python
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import os
import xlrd
from lxml import etree
from lxml import isoschematron

class SchematronValidator(object):
	def __init__(self, schematron=None):
		self.schematron = None
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
		
		self.schematron = isoschematron.Schematron(tree)
	
	def _element_to_file(self, tree, fn):	
		with open(fn, "wb") as f:
			f.write(etree.tostring(tree, pretty_print=True))
	
	def _build_result_dict(self, result, errors=None):
		d = {}
		d['result'] = result
		if errors:
			d['errors'] = errors
		return d
	
	def _build_error_list(self, validation_report):
		errors = isoschematron.svrl_validation_errors(validation_report)
		return [etree.tounicode(x) for x in errors]
	
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
				errors = self._build_error_list(self.schematron.validation_report)
				return self._build_result_dict(result, errors)
			else:
				return self._build_result_dict(result)
			
		except etree.ParseError as e:
			return self._build_result_dict(False, [str(e)])	


class ProfileValidator(SchematronValidator):
	NS_SCHEMATRON = "http://purl.oclc.org/dsdl/schematron"
	PREFIX_SCHEMATRON = "sch"
	
	def __init__(self, profile_fn):
		super(ProfileValidator, self).__init__()
		self.sheets = {}
		self.profile_workbook = self._open_profile(profile_fn)
		self.schema = self._parse_profile()
		
	
	def _parse_profile(self):
		root = etree.Element("{%s}schema" % self.NS_SCHEMATRON, nsmap={None:self.NS_SCHEMATRON})
		
		for s in self.profile_workbook.sheet_names():
			self.sheets[self._convert_to_string(s)] = self.profile_workbook.sheet_by_name(s)
		
		
		pattern = self._add_element(root, "pattern", id="STIX_Schematron_Profile")
		for i in range(1, self.sheets["Sheet2"].nrows):
			if self._get_cell_value("Sheet2", col=2, row=i) != "":
				rule = self._add_element(pattern, "rule")
				if self._get_cell_value("Sheet2", col=0, row=i)[0] == "@":
					self._cell_to_node(rule, "Sheet2", col=1, row=i, attr_name="context", type="attribute", type_arg=self._get_cell_value("Sheet2", col=0, row=i))
				else:
					self._cell_to_node(rule, "Sheet2", col=1, row=i, attr_name="context")
				if self._get_cell_value("Sheet2", col=2, row=i) == "required":
					test = self._add_element(rule, "assert", text="This field is required for this STIX profile.")
					self._cell_to_node(test, "Sheet2", col=0, row=i, attr_name="test", type="required", role="error")
					if self._get_cell_value("Sheet2", col=3, row=i) != "":
						test = self._add_element(rule, "assert", text="The required xsi:type for this field is: "+self._get_cell_value("Sheet2", col=3, row=i))
						self._cell_to_node(test, "Sheet2", col=3, row=i, attr_name="test", type="xsi", type_arg=self._get_cell_value("Sheet2", col=0, row=i))
					if self._get_cell_value("Sheet2", col=4, row=i) != "":
						test = self._add_element(rule, "assert", text="The required value for this field is: "+self._get_cell_value("Sheet2", col=4, row=i))
						self._cell_to_node(test, "Sheet2", col=4, row=i, attr_name="test", type="value", type_arg=self._get_cell_value("Sheet2", col=0, row=i))
						
				if self._get_cell_value("Sheet2", col=2, row=i) == "prohibited":
					test = self._add_element(rule, "assert", text="This field is prohibited for this STIX profile.")
					self._cell_to_node(test, "Sheet2", col=0, row=i, attr_name="test", type="prohibited")
				
				if self._get_cell_value("Sheet2", col=2, row=i) == "optional":
					test = self._add_element(rule, "assert", text="This field is optional for this STIX profile.")
					self._cell_to_node(test, "Sheet2", col=0, row=i, attr_name="test", type="required", role="warning")

		self._unload_workbook()
		return root
		
	def _cell_to_node(self, par, sheet, col, row, attr_name=None, type=None, type_arg=None, role=None):
		s = self.sheets.get(sheet)
		if not s:
			raise Exception("%s not in workbook." % sheet)
		v = self._convert_to_string(s.row_values(row)[col])
		if role:
			par.set("role", role)
		if type=="required":
			par.set(attr_name, v)
		elif type=="prohibited":
			par.set(attr_name, "not(" + v + ")")
		elif type=="xsi":
			par.set(attr_name, "//"+type_arg+"[@xsi:type='" + v + "']")
		elif type=="value":
			par.set(attr_name, type_arg+"='"+v+"'")
		elif type=="attribute":
			par.set(attr_name, v+"["+type_arg+"]")
		else:
			par.set(attr_name, v)
			
	def _map_ns(self, instance, schematron):
		nsmap = instance.nsmap
		for prefix, ns in nsmap.iteritems():
			ns_element = etree.Element("{%s}ns" % self.NS_SCHEMATRON)
			ns_element.set("prefix", prefix)
			ns_element.set("uri", ns)
			schematron.insert(0, ns_element)
			
	def _add_element(self, node, sub, text=None, **kwargs):
		child = etree.SubElement(node, "{%s}%s" % (self.NS_SCHEMATRON, sub))
		if text:
			child.text = text
		for k,v in kwargs.iteritems():
			child.set(k, v)
		return child
	
	def _unload_workbook(self):
		for k,v in self.sheets.iteritems():
			self.profile_workbook.unload_sheet(k)
			
	def _get_cell_value(self, sheet, col, row):
		s = self.sheets.get(sheet)
		if not s:
			raise Exception("%s not in workbook." % sheet)
		value = s.cell_value(row, col)
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
	
	def validate(self, instance):
		if isinstance(instance, etree._Element):
			root = instance
		elif isinstance(instance, etree._ElementTree):
			root = instance.getroot()
		else:
			tree_in = etree.parse(instance)
			root = tree_in.getroot()
		
		working_schema = self._get_schema_copy()
		self._map_ns(root, working_schema)
		
		super(ProfileValidator, self).init_schematron(working_schema)
		return super(ProfileValidator, self).validate(tree_in)

