#!/usr/bin/env python

# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import os
import sys
import xlrd
from exceptions import Exception
from lxml import etree
from lxml import isoschematron
import libxml2

class schematron(object):
	doc = None
	sheets = {}
	workbook = None
	
	def __init__(self, filename=None):
		self.workbook=self._open_workbook(filename)
		for s in self.workbook.sheet_names():
			self.sheets[self._convert_to_string(s)] = self.workbook.sheet_by_name(s)
		
	
	def cell_to_node(self, par, sheet, col, row, attr_name=None, type=None, type_arg=None, role=None):
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
	
	def create_root_node(self, root_node, **kargs):
		self.doc = etree.Element(root_node)
		for k, v in kargs.items():
			self.doc.set(k, v)
			
	def map_ns(self, instance_doc):
		doc=etree.parse(instance_doc)
		doc_root=doc.getroot()
		nsmap = doc_root.nsmap
		for name, value in nsmap.items():
			ns = etree.SubElement(self.doc, "ns")
			ns.set("prefix", name)
			ns.set("uri", value)
			
	def add_element(self, node, sub, text=None, **kargs):
		child = etree.SubElement(node, sub)
		if text:
			child.text=text
		for k, v in kargs.items():
			child.set(k, v)
		return child
	
	def done(self):
		for k, v in self.sheets.items():
			self.workbook.unload_sheet(k)
	
			
	def get_cell_value(self, sheet, col, row):
		s=self.sheets.get(sheet)
		if not s:
			raise Exception("%s not in workbook." % sheet)
		value = s.cell_value(row, col)
		return value
	
	def save_to_file(self, input_file, filename, overwrite=False):
		if not overwrite and os.path.isfile(filename):
			raise Exception("\t\tFile already exists.")
		f = open(filename, "w")
		f.write(etree.tostring(input_file, pretty_print=True))
		f.close()
		print "\t\tFile saved as: " + os.path.realpath(filename)
	
	def _convert_to_string(self, value):
		if type(value) is unicode:
			return value.encode("UTF-8")
		else:
			return str(value)
	
	def _open_workbook(self, filename):
		if not filename:
			filename = sys.argv[-1]
		if filename[-5:].lower() != ".xlsx":
			raise Exception("\tFile name is not a .xlsx file.")
		try:
			return xlrd.open_workbook(filename)
		except:
			raise Exception("\tFile does not seem to be valid XLSX.")
			
	def validate_schematron(self, filename, store_schematron, store_xslt, store_report):
		try:
			tree=etree.ElementTree(self.doc)
			doc = etree.tostring(tree)
			schematron = isoschematron.Schematron(etree.XML(doc), store_report=store_report, store_xslt=store_xslt, store_schematron=store_schematron)
		except etree.SchematronParseError, e:
			print e.args
			print e.error_log
			print e.message
			return (None, None, None)
		try:
			file = etree.parse(filename)
			if store_xslt:
				print "\tGenerating XSLT..."
				transform = etree.XSLT(schematron.validator_xslt)
				self.save_to_file(schematron.validator_xslt, os.path.splitext(filename)[0]+".xslt", True)
			result=schematron.validate(file)
			if store_schematron:
				print "\tGenerating Schematron..."
				self.save_to_file(schematron.schematron, os.path.splitext(filename)[0]+".sch", True)
			if store_report:
				print "\tGenerating Validation Report..."
				self.save_to_file(schematron.validation_report, os.path.splitext(filename)[0]+".doc", True)
				errors = isoschematron.svrl_validation_errors(schematron.validation_report)
				for error in errors:
					#print schematron._domain
					#print schematron._level
					#print schematron._error_type
					#print etree.tounicode(error)
					return (result, etree.tounicode(error), None)
			return (result, None, None)
		except etree.ParseError, e:
			print e.args
			print e.error_log
			print e.message
			return (None, None, None)
			
class SchematronValidator(schematron):
	def __init__(self, instance_doc, profile=None):
		super(SchematronValidator, self).__init__(profile)

		self.create_root_node("schema", xmlns="http://purl.oclc.org/dsdl/schematron")
		self.map_ns(instance_doc)
		
		pattern = self.add_element(self.doc, "pattern", id="STIX_Schematron_Profile")
		for i in range(1, self.sheets["Sheet2"].nrows):
			
			if self.get_cell_value("Sheet2", col=2, row=i) != "":
				rule = self.add_element(pattern, "rule")
				if self.get_cell_value("Sheet2", col=0, row=i)[0] == "@":
					self.cell_to_node(rule, "Sheet2", col=1, row=i, attr_name="context", type="attribute", type_arg=self.get_cell_value("Sheet2", col=0, row=i))
				else:
					self.cell_to_node(rule, "Sheet2", col=1, row=i, attr_name="context")
				if self.get_cell_value("Sheet2", col=2, row=i) == "required":
					test = self.add_element(rule, "assert", text="This field is required for this STIX profile.")
					self.cell_to_node(test, "Sheet2", col=0, row=i, attr_name="test", type="required", role="error")
					if self.get_cell_value("Sheet2", col=3, row=i) != "":
						test = self.add_element(rule, "assert", text="The required xsi:type for this field is: "+self.get_cell_value("Sheet2", col=3, row=i))
						self.cell_to_node(test, "Sheet2", col=3, row=i, attr_name="test", type="xsi", type_arg=self.get_cell_value("Sheet2", col=0, row=i))
					if self.get_cell_value("Sheet2", col=4, row=i) != "":
						test = self.add_element(rule, "assert", text="The required value for this field is: "+self.get_cell_value("Sheet2", col=4, row=i))
						self.cell_to_node(test, "Sheet2", col=4, row=i, attr_name="test", type="value", type_arg=self.get_cell_value("Sheet2", col=0, row=i))
						
				if self.get_cell_value("Sheet2", col=2, row=i) == "prohibited":
					test = self.add_element(rule, "assert", text="This field is prohibited for this STIX profile.")
					self.cell_to_node(test, "Sheet2", col=0, row=i, attr_name="test", type="prohibited")
				
				if self.get_cell_value("Sheet2", col=2, row=i) == "optional":
					test = self.add_element(rule, "assert", text="This field is optional for this STIX profile.")
					self.cell_to_node(test, "Sheet2", col=0, row=i, attr_name="test", type="required", role="warning")

		self.done()
		
	def validate_schematron(self, instance_doc, store_schematron, store_xslt, store_report):
		(isvalid, validation_error, best_practice_warnings) = super(SchematronValidator, self).validate_schematron(instance_doc, store_schematron, store_xslt, store_report)
		return (isvalid, validation_error, best_practice_warnings)