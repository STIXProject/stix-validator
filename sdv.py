#!/usr/bin/env python

# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
'''
STIX Document Validator (sdv) - validates STIX v1.1.1 instance documents.
'''

import os
import argparse
import json
from validators import STIXValidator, ProfileValidator

__version__ = "1.1.1.0"
QUIET_OUTPUT = False

def get_files_to_validate(dir):
    '''Return a list of xml files under a directory'''
    to_validate = []
    for fn in os.listdir(dir):
        if fn.endswith('.xml'):
            fp = os.path.join(dir, fn)
            to_validate.append(fp)
            
    return to_validate

def error(msg):
    '''Print the error message and exit(1)'''
    print "[!] %s" % (msg)
    exit(1)

def info(msg):
    '''Prints an info message'''
    if QUIET_OUTPUT: 
        return
    print "[-] %s" % msg

def print_schema_results(fn, results):
    if results['result']:
        print "[+] XML schema validation results: %s : VALID" % fn
        warnings = results.get('best_practice_warnings')
        if warnings:
            print "[-] Best Practice Warnings"
            root_element = warnings.get('root_element')
            if root_element:
                print '    [#] Root element not STIX_Package: [%s]' % (root_element['tag'])

            duplicate_ids = warnings.get('duplicate_ids')
            if duplicate_ids:
                print '    [#] Nodes with duplicate ids'
                for id_, list_nodes in duplicate_ids.iteritems():
                    print '    [~] id: [%s]' % (id_)
                    for node in list_nodes:
                        print '       [%s] line: [%s]' % (node['tag'], node['line_number'])
      
            missing_ids = warnings.get('missing_ids')
            if missing_ids:
                print '    [#] Nodes with missing ids'
                for node in missing_ids:
                    print '    [~] [%s] line: [%s]' % (node['tag'], node['line_number'])
    
            unresolved_idrefs = warnings.get('unresolved_idrefs')
            if unresolved_idrefs:
                print '    [#] Nodes with idrefs that do not resolve'
                for node in unresolved_idrefs:
                    print '    [~] [%s] idref: [%s] line: [%s]' % (node['tag'], node['idref'], node['line_number'])
          
            formatted_ids = warnings.get('id_format')
            if formatted_ids:
                print '    [#] Nodes with ids not formatted as [ns_prefix]:[object-type]-[GUID]'
                for node in formatted_ids:
                    print '    [~] [%s] id: [%s] line: [%s]' % (node['tag'], node['id'], node['line_number'])

            idrefs_with_content = warnings.get('idref_with_content')
            if idrefs_with_content:
                print '    [#] Nodes that declare idrefs but also contain content'
                for node in idrefs_with_content:
                    print '    [~] [%s] idref: [%s] line: [%s]' % (node['tag'], node['idref'], node['line_number'])
                
            indicator_suggestions = warnings.get('indicator_suggestions')
            if indicator_suggestions:
                print '    [#] Indicator suggestions'
                for node in indicator_suggestions:               
                    print '    [~] id: [%s] line: [%s] missing: %s' % (node['id'], node['line_number'], node.get('missing'))
                    
    else:
        print "[!] XML schema validation results: %s : INVALID" % fn
        print "[!] Validation errors"
        for error in results.get("errors", []):
            print "    [!] %s" % (error)
                 
def print_profile_results(fn, results):
    report = results.get('report', {})
    errors = report.get('errors')
    if not errors:
        print "[+] Profile validation results: %s : VALID" % fn
    else:
        print "[!] Profile validation results: %s : INVALID" % fn
        print "[!] Profile Errors"
        for error in sorted(errors, key=lambda x: x['error']):
            msg = error.get('error')
            line_numbers = error['line_numbers']
            line_numbers.sort()
            print "    [!] %s [%s]" % (msg, ', '.join(line_numbers))
            
def convert_profile(validator, xslt_out_fn=None, schematron_out_fn=None):
    xslt = validator.get_xslt()
    schematron = validator.get_schematron()
    
    if schematron_out_fn:
        info("Writing schematron conversion of profile to %s" % schematron_out_fn)
        schematron.write(schematron_out_fn, pretty_print=True, xml_declaration=True, encoding="UTF-8")
    if xslt_out_fn:
        info("Writing xslt conversion of profile to %s" % xslt_out_fn)
        xslt.write(xslt_out_fn, pretty_print=True, xml_declaration=True, encoding="UTF-8")
        
def main():
    parser = argparse.ArgumentParser(description="STIX Document Validator")
    parser.add_argument("--schema-dir", dest="schema_dir", default=None, help="Path to directory containing all necessary schemas for validation")
    parser.add_argument("--input-file", dest="infile", default=None, help="Path to STIX instance document to validate")
    parser.add_argument("--input-dir", dest="indir", default=None, help="Path to directory containing STIX instance documents to validate")
    parser.add_argument("--use-schemaloc", dest="use_schemaloc", action='store_true', default=False, help="Use schemaLocation attribute to determine schema locations.")
    parser.add_argument("--best-practices", dest="best_practices", action='store_true', default=False, help="Check that the document follows authoring best practices")
    parser.add_argument("--profile", dest="profile", default=None, help="Path to STIX profile in excel")
    parser.add_argument("--schematron-out", dest="schematron", default=None, help="Path to converted STIX profile schematron file output")
    parser.add_argument("--xslt-out", dest="xslt", default=None, help="Path to converted STIX profile schematron xslt output")
    parser.add_argument("--quiet", dest="quiet", action="store_true", default=False, help="Only print results and errors if they occur")
    parser.add_argument("--json-results", dest="json", action="store_true", default=False, help="Print results as raw JSON. This also sets --quiet.")
    
    args = parser.parse_args()
    global QUIET_OUTPUT
    QUIET_OUTPUT = args.quiet or args.json
    schema_validation = False
    profile_validation = False
    profile_conversion = False
    
    if (args.infile or args.indir) and (args.schema_dir or args.use_schemaloc):
        schema_validation = True
        if args.profile:
            profile_validation = True
        
    if args.profile and (args.schematron or args.xslt):
        profile_conversion = True
    
    if args.infile and args.indir:
        error('Must provide either --input-file or --input-dir argument, but not both')
    if args.schema_dir and args.use_schemaloc:
        error("Must provide either --use-schemaloc or --schema-dir, but not both")
    if (args.infile or args.indir) and not (args.schema_dir or args.use_schemaloc):
        error("Must provide either --use-schemaloc or --schema-dir when --input-file or input-dir declared")
    if args.profile and not (profile_validation or profile_conversion):
        error("Profile specified but no conversion options or validation options specified")
    
    try:
        if profile_validation or profile_conversion:
            profile_validator = ProfileValidator(args.profile)
        
        if schema_validation:
            if args.infile:
                to_validate = [args.infile]
            elif args.indir:
                to_validate = get_files_to_validate(args.indir)
            else:
                to_validate = []
            
            if len(to_validate) > 0:
                info("Processing %s files" % (len(to_validate)))
                stix_validator = STIXValidator(schema_dir=args.schema_dir, use_schemaloc=args.use_schemaloc, best_practices=args.best_practices)
                for fn in to_validate:
                    schema_results = {}
                    profile_results = {}
                    
                    info("Validating STIX document %s against XML schema... " % fn)
                    schema_results = stix_validator.validate(fn)
                    isvalid = schema_results['result']
                    
                    if profile_validation:
                        if isvalid:
                            info("Validating STIX document %s against profile %s..." % (fn, args.profile))
                            profile_results = profile_validator.validate(fn)
                        else: 
                            info("The document %s was schema-invalid. Skipping profile validation" % fn) 
                    
                    if args.json:
                        json_results = {}
                        if schema_results:
                            json_results['schema_validation'] = schema_results
                        if profile_results:
                            json_results['profile_results'] = profile_results
                        
                        print json.dumps(json_results)
                    else:
                        if schema_results: print_schema_results(fn, schema_results)
                        if profile_results: print_profile_results(fn, profile_results)
                    
        if profile_conversion:
            convert_profile(profile_validator, xslt_out_fn=args.xslt, schematron_out_fn=args.schematron)

    except Exception as ex:
        error("Fatal error occurred: %s" % str(ex))
    
if __name__ == '__main__':
    main()

    