#!/usr/bin/env python

# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
'''
STIX Document Validator (sdv) - validates STIX v1.1.1 instance documents.
'''

import sys
import os
import logging
import argparse
import json
import settings
from validators import (STIXSchemaValidator, STIXProfileValidator,
                        STIXBestPracticeValidator)

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

def print_level(fmt, level, *args):
    msg = fmt % args
    spaces = '    ' * level
    print "%s%s" % (spaces, msg)

def print_schema_results(fn, results):
    if results['result']:
        print_level("[+] XML schema validation results: %s : VALID", 0, fn)
    else:
        print_level("[!] XML schema validation results: %s : INVALID", 0, fn)
        print_level("[!] Validation errors", 0)
        for error in results.get("errors", []):
            print_level("[!] %s",1 ,error)

def print_best_practice_results(fn, results):
    if results['result']:
        print "[+] Best Practice validation results: %s : VALID" % fn
    else:
        print_level("[!] Best Practice validation results: %s : INVALID", 0, fn)
        print_level("[!] Best Practice warnings", 0)
        if 'fatal' in results:
            print_level("[!] Fatal error occurred processing best practices: "
                        "%s", 1, results['fatal'])
            return
        
        warnings = results.get('warnings', {})
        root_element = warnings.get('root_element')
        if root_element:
            print_level("[#] Root element not STIX_Package: [%s]", 1,
                        root_element['tag'])

        duplicate_ids = warnings.get('duplicate_ids')
        if duplicate_ids:
            print_level("[#] Nodes with duplicate ids", 1)
            for id_, list_nodes in duplicate_ids.iteritems():
                print_level("[~] id: [%s]", 2, id_)
                for node in list_nodes:
                    print_level("[%s] line: [%s]", 3, node['tag'], 
                                node['line_number'])

        missing_ids = warnings.get('missing_ids')
        if missing_ids:
            print_level("[#] Nodes with missing ids", 1)
            for node in missing_ids:
                print_level("[~] [%s] line: [%s]", 2, node['tag'], 
                            node['line_number'])

        unresolved_idrefs = warnings.get('unresolved_idrefs')
        if unresolved_idrefs:
            print_level("[#] Nodes with idrefs that do not resolve", 1)
            for node in unresolved_idrefs:
                print_level("[~] [%s] idref: [%s] line: [%s]", 2, node['tag'], 
                            node['idref'], node['line_number'])

        formatted_ids = warnings.get('id_format')
        if formatted_ids:
            print_level("[#] Nodes with ids not formatted as [ns_prefix]:"
                        "[object-type]-[GUID]", 1)
            for node in formatted_ids:
                print_level("[~] [%s] id: [%s] line: [%s]", 2, node['tag'], 
                            node['id'], node['line_number'])

        idrefs_with_content = warnings.get('idref_with_content')
        if idrefs_with_content:
            print_level("[#] Nodes that declare idrefs but also contain "
                        "content", 1)
            for node in idrefs_with_content:
                print_level("[~] [%s] idref: [%s] line: [%s]", 2, node['tag'], 
                            node['idref'], node['line_number'])

        indicator_suggestions = warnings.get('indicator_suggestions')
        if indicator_suggestions:
            print_level("[#] Indicator suggestions", 1)
            for node in indicator_suggestions:
                print_level("[~] id: [%s] line: [%s] missing: %s", 2, 
                            node['id'], node['line_number'],
                            node.get('missing'))

        missing_titles = warnings.get('missing_titles')
        if missing_titles:
            print_level("[#] Missing Titles", 1)
            for node in missing_titles:
                print_level("[~] [%s] id: [%s] line: [%s]", 2,
                            node['tag'], node['id'], node['line_number'])

def print_profile_results(fn, results):
    report = results.get('report', {})
    errors = report.get('errors')
    if not errors:
        print_level("[+] Profile validation results: %s : VALID", 0, fn)
    else:
        print_level("[!] Profile validation results: %s : INVALID", 0, fn)
        print_level("[!] Profile Errors", 0)
        for error in sorted(errors, key=lambda x: x['error']):
            msg = error.get('error')
            line_numbers = error['line_numbers']
            line_numbers.sort()
            print_level("[!] %s [%s]", 1, msg, ', '.join(line_numbers))
            
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
    parser.add_argument("--stix-version", dest="stix_version", default=None, help="The version of STIX to validate against")
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

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    global QUIET_OUTPUT
    QUIET_OUTPUT = args.quiet or args.json
    schema_validation = False
    profile_validation = False
    profile_conversion = False

    if (args.infile or args.indir) and (settings.SCHEMAS or args.use_schemaloc):
        schema_validation = True
        if args.profile:
            profile_validation = True
    else:
        error("Invalid schema validation options")


    if args.profile and (args.schematron or args.xslt):
        profile_conversion = True
    
    if args.infile and args.indir:
        error('Must provide either --input-file or --input-dir argument, but not both')
    if (args.infile or args.indir) and not (settings.SCHEMAS or args.use_schemaloc):
        error("Must provide either --use-schemaloc or settings.SCHEMAS when --input-file or input-dir declared")
    if args.profile and not (profile_validation or profile_conversion):
        error("Profile specified but no conversion options or validation options specified")
    
    try:
        if profile_validation or profile_conversion:
            profile_validator = STIXProfileValidator(args.profile)

        if args.best_practices:
            bp_validator = STIXBestPracticeValidator()

        if schema_validation:
            if args.infile:
                to_validate = [args.infile]
            elif args.indir:
                to_validate = get_files_to_validate(args.indir)
            else:
                to_validate = []
            
            if len(to_validate) > 0:
                info("Processing %s files" % (len(to_validate)))
                schema_validator = STIXSchemaValidator(schemas=settings.SCHEMAS)
                for fn in to_validate:
                    schema_results = {}
                    best_practice_results = {}
                    profile_results = {}
                    
                    info("Validating STIX document %s against XML schema... " % fn)
                    schema_results = schema_validator.validate(fn, version=args.stix_version, schemaloc=args.use_schemaloc)
                    isvalid = schema_results['result']

                    if args.best_practices:
                        if isvalid:
                            best_practice_results = bp_validator.validate(fn, args.stix_version)
                        else:
                            info("The document %s was schema-invalid: Skipping "
                                 "best practice validation" % fn)

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
                        if best_practice_results:
                            json_results['best_practice_results'] = best_practice_results

                        print json.dumps(json_results)
                    else:
                        if schema_results:
                            print_schema_results(fn, schema_results)
                        if best_practice_results:
                            print_best_practice_results(fn, best_practice_results)
                        if profile_results:
                            print_profile_results(fn, profile_results)
                    
        if profile_conversion:
            convert_profile(profile_validator, xslt_out_fn=args.xslt, schematron_out_fn=args.schematron)

    except Exception as ex:
        logging.exception("Error occurred")
        #error("Fatal error occurred: %s" % str(ex))
    
if __name__ == '__main__':
    main()

    