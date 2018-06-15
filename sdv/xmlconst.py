# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
"""This file defines constants to be used in XML processing code."""

# Namespaces
NS_SAXON = "http://icl.com/saxon"   # libxml2 requires this namespace
NS_SAXON_SF_NET = "http://saxon.sf.net/"
NS_SCHEMATRON = "http://purl.oclc.org/dsdl/schematron"
NS_SVRL = "http://purl.oclc.org/dsdl/svrl"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
NS_XML_SCHEMA = "http://www.w3.org/2001/XMLSchema"

# LXML QNAMES TAGS
TAG_XS_INCLUDE = "{%s}include" % (NS_XML_SCHEMA)
TAG_XS_IMPORT = "{%s}import" % (NS_XML_SCHEMA)
TAG_XSI_TYPE = "{%s}type" % (NS_XSI)
TAG_SCHEMALOCATION = "{%s}schemaLocation" % NS_XSI
TAG_SVRL_FIRED_RULE = "{%s}fired-rule" % NS_SVRL
TAG_SVRL_FAILED_ASSERT = "{%s}failed-assert" % NS_SVRL
TAG_SVRL_SUCCESSFUL_REPORT = "{%s}successful-report" % NS_SVRL


# Common XPaths
XPATH_RELATIVE_CHILDREN = "./*"
XPATH_RELATIVE_DESCENDANTS = ".//*"
