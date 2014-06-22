# STIX Document Validator (sdv)
A python tool used to validate STIX instance documents. For more information about the
Structured Threat Information eXpression, see http://stix.mitre.org.

## Dependencies
The STIX Document Validator has the following dependencies:
* Python v2.7 http://python.org/download
* lxml >= v3.2.0 http://lxml.de/index.html#download
  * libxml2 >= v2.9.1 http://www.xmlsoft.org/downloads.html
* xlrd >= v0.9.2 https://pypi.python.org/pypi/xlrd

For a Windows installer of lxml, we recommend looking here: http://www.lfd.uci.edu/~gohlke/pythonlibs/#lxml

## Common Libxml2 Error
Users often report an error which looks something like the following:
```
Fatal error occurred: local union type: A type, derived by list or union, must have the 
simple ur-type definition as base type, not '{http://cybox.mitre.org/common-2}(NULL)'., line 350
```
This error is caused by an insufficient version of libxml2 being installed on the system. The 
stix-validator requires libxml2 v2.9.1 at a minimum and is not guaranteed to work properly with
earlier versions. 

To see what version of libxml2 you have installed, execute the `xml2-config --version` command
and make sure you are running at least v2.9.1.

## Use
The STIX Document Validator can validate a STIX instance document against STIX schemas
found locally or referenced remotely through the schemaLocation attribute. It can also perform
some 'best practice' guidance checks and STIX Profile validation and conversion to XSLT/Schematron.

**NOTE:** The STIX Profile validation and conversion capabilities should be considered **experimental.**

**Validate using local schemas**  
`python sdv.py --input-file <stix_document.xml>`

**Validate using schemaLocation**  
`python sdv.py --input-file <stix_document.xml> --use-schemaloc`

**Validate a directory of STIX documents**  
`python sdv.py --input-dir <stix_dir>`

**Check "best practice" guidance**  
`python sdv.py --input-file <stix_document.xml> --best-practices`

**Validate using STIX Profile**  
`python sdv.py --input-file <stix_document.xml> --profile <stix_profile.xlsx>`

**Translate STIX Profile to XSLT/Schematron**  
`python sdv.py --profile <stix_profile.xlsx> --xslt-out <stix_profile.xslt> --schematron-out <stix_profile.sch>`

## All STIX Documents?
The STIX Document Validator bundles a schema directory with it, which includes all STIX 
schema files (v1.0 through v1.1.1). If an instance document uses constructs or languages defined by other schemas
a user must point the STIX Document Validator at those schemas in order to validate.

To do this, you'll need to modify the `settings.py` file to include or override an entry in the `SCHEMAS`
dictionary. 

Example:
```python
# Format: { STIX VERSION : SCHEMA DIRECTORY }
SCHEMAS = {'1.1.1': 'schemas/your_custom_schema_dir'}
```

## Terms
BY USING THE STIX DOCUMENT VALIDATOR, YOU SIGNIFY YOUR ACCEPTANCE OF THE 
TERMS AND CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE 
THE STIX DOCUMENT VALIDATOR.

For more information, please refer to the LICENSE.txt file
