#!/usr/bin/env python

# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
'''
STIX Document Validator (sdv) - validates STIX v1.0.1 instance documents.
'''

import os
import argparse
from validators import STIXValidator, ProfileValidator

def get_files_to_validate(dir):
    '''Return a list of xml files under a directory'''
    to_validate = []
    for fn in os.listdir(dir):
        if fn.endswith('.xml'):
            fp = os.path.join(dir, fn)
            to_validate.append(fp)
            True
    
    return to_validate

def error(msg):
    '''Print the error message and exit(1)'''
    print "[!] %s" % (msg)
    exit(1)

def print_result(fp, isvalid, validation_error, warnings):
    if isvalid:
        print "[+] %s : VALID\n" % (fp)
        
        if warnings:
            root_element = warnings.get('root_element')
            if root_element is not None:
                print '    [#] Root element not STIX_Package: [%s]' % (root_element.tag)

            duplicate_ids = warnings.get('duplicate_ids')
            if duplicate_ids:
                print '    [#] Nodes with duplicate ids'
                for id_, list_nodes in duplicate_ids.iteritems():
                    print '    [~] id: [%s]' % (id_)
                    for node in list_nodes:
                        print '       [%s] line: [%s]' % (node.tag, node.sourceline)
      
            missing_ids = warnings.get('missing_ids')
            if missing_ids:
                print '    [#] Nodes with missing ids'
                for node in missing_ids:
                    print '    [~] [%s] line: [%s]' % (node.tag, node.sourceline)
    
            unresolved_idrefs = warnings.get('unresolved_idrefs')
            if unresolved_idrefs:
                print '    [#] Nodes with idrefs that do not resolve'
                for node in unresolved_idrefs:
                    print '    [~] [%s] idref: [%s] line: [%s]' % (node.tag, node.attrib.get('idref'), node.sourceline)
          
            formatted_ids = warnings.get('id_format')
            if formatted_ids:
                print '    [#] Nodes with ids not formatted as [ns_prefix]:[object-type]-[GUID]'
                for node in formatted_ids:
                    print '    [~] [%s] id: [%s] line: [%s]' % (node.tag, node.attrib.get('id'), node.sourceline)

            idrefs_with_content = warnings.get('idref_with_content')
            if idrefs_with_content:
                print '    [#] Nodes that declare idrefs but also contain content'
                for node in idrefs_with_content:
                    print '    [~] [%s] idref: [%s] line: [%s]' % (node.tag, node.attrib.get('idref'), node.sourceline)
                
            indicator_suggestions = warnings.get('indicator_suggestions')
            if indicator_suggestions:
                print '    [#] Indicator suggestions'
                for indicator_dict in indicator_suggestions:
                    node = indicator_dict['node']                    
                    print '    [~] id: [%s] line: [%s] missing: %s' % (indicator_dict.get('id'), node.sourceline, indicator_dict.get('missing'))
                    
    else:
        print "[!] %s : INVALID : [%s]" % (fp, str(validation_error))
                    


def main():
    parser = argparse.ArgumentParser(description="STIX Document Validator")
    parser.add_argument("--schema-dir", dest="schema_dir", default=None, help="Path to directory containing all necessary schemas for validation")
    parser.add_argument("--input-file", dest="infile", default=None, help="Path to STIX instance document to validate")
    parser.add_argument("--input-dir", dest="indir", default=None, help="Path to directory containing STIX instance documents to validate")
    parser.add_argument("--use-schemaloc", dest="use_schemaloc", action='store_true', default=False, help="Use schemaLocation attribute to determine schema locations.")
    parser.add_argument("--best-practices", dest="best_practices", action='store_true', default=False, help="Check that the document follows authoring best practices")
    parser.add_argument("--profile", dest="profile", default=None, help="Path to STIX profile in excel")
    parser.add_argument("--store-xslt", dest="store_xslt", action='store_true', default=False, help="Store the schematron xsl transform")
    parser.add_argument("--store-schematron", dest="store_schematron", action='store_true', default=False, help="Store the schematron schema")
    parser.add_argument("--store-report", dest="store_report", action='store_true', default=False, help="Store the schematron validation report")
    
    args = parser.parse_args()
    
    if not(args.infile or args.indir):
        error("Must provide either --input-file or --input-dir argument")
    
    if args.infile and args.indir:
        error('Must provide either --input-file or --input-dir argument, but not both')
    
    if not(args.schema_dir or args.use_schemaloc):
        error("Must provide either --use-schemaloc or --schema-dir")
        
    if args.schema_dir and args.use_schemaloc:
        error("Must provide either --use-schemaloc or --schema-dir, but not both")
        
    if not(args.profile):
        if args.store_schematron or args.store_xslt or args.store_report:
            error("Must provide schematron profile")
         
    if args.infile:
        to_validate = [args.infile]
    else:
        to_validate = get_files_to_validate(args.indir)
    
    if len(to_validate) > 0:
        print "[-] Processing %s files" % (len(to_validate))
        ssv = STIXValidator(schema_dir=args.schema_dir, use_schemaloc=args.use_schemaloc, best_practices=args.best_practices)
        for fn in to_validate:
            with open(fn, 'rb') as f:
                print "Validating STIX document: " + fn
                (isvalid, validation_error, best_practice_warnings) = ssv.validate(f)
                print_result(fn, isvalid, validation_error, best_practice_warnings)
                if args.profile and isvalid:
                        print "Validating STIX document against Schematron profile: " + fn
                        profile_validator = ProfileValidator(args.profile)
                        results = profile_validator.validate(fn)
                        print results
                        #print_result(fp, isvalid, validation_error, best_practice_warnings)
                elif args.profile and not(isvalid): 
                    print "\tThe STIX document was invalid, so it was not validated against the Schematron profile"

if __name__ == '__main__':
    main()

    