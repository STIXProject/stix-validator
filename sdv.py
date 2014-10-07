#!/usr/bin/env python

# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from gooey import Gooey

import sys
import os
import logging
import argparse
import json
import settings
from validators import (STIXSchemaValidator, STIXProfileValidator,
                        STIXBestPracticeValidator)

__version__ = "1.1.1.2"

QUIET_OUTPUT = False

EXIT_SUCCESS = 0
EXIT_FAILURE = 1


class ValidationOptions(object):
    def __init__(self):
        # validation options
        self.schema_validate = False
        self.use_schemaloc = False
        self.stix_version = None
        self.profile_validate = False
        self.best_practice_validate = False

        # conversion options
        self.profile_convert = False
        self.xslt_out = None
        self.schematron_out = None

        # output options
        self.json_results = False
        self.quiet_output = False

        # input options
        self.in_files = None
        self.in_profile = None

        # self.in_schemas = None # Not supported yet.


class ValidationResults(object):
    def __init__(self, fn=None):
        self.fn = fn
        self.schema_results = None
        self.best_practice_results = None
        self.profile_results = None


class ArgumentError(Exception):
    def __init__(self, msg=None, show_help=False):
        super(ArgumentError, self).__init__(msg)
        self.show_help = show_help


class SchemaInvalidError(Exception):
    def __init__(self, msg=None, results=None):
        super(SchemaInvalidError, self).__init__(msg)
        self.results = results


def _error(msg):
    sys.stdout.write("\n[!] %s\n" % str(msg))
    exit(EXIT_FAILURE)


def _info(msg):
    if QUIET_OUTPUT:
        return
    print "[-] %s" % msg


def _print_level(fmt, level, *args):
    msg = fmt % args
    spaces = '    ' * level
    print "%s%s" % (spaces, msg)


def _get_dir_files(dir_):
    files = []
    for fn in os.listdir(dir_):
        if fn.endswith('.xml'):
            fp = os.path.join(dir_, fn)
            files.append(fp)

    return files

def _get_files_to_validate(options):
    files = options.in_files

    if not files:
        return []

    to_validate = []
    for fn in files:
        if os.path.isdir(fn):
            children = _get_dir_files(fn)
            to_validate.extend(children)
        else:
            to_validate.append(fn)

    return to_validate


def _set_output_level(options):
    global QUIET_OUTPUT
    QUIET_OUTPUT = options.quiet_output or options.json_results


def _print_schema_results(fn, results):
    if results['result']:
        _print_level("[+] XML schema validation results: %s : VALID", 0, fn)
    else:
        _print_level("[!] XML schema validation results: %s : INVALID", 0, fn)
        _print_level("[!] Validation errors", 0)
        for error in results.get("errors", []):
            _print_level("[!] %s", 1, error)


def _print_best_practice_results(fn, results):
    if results['result']:
        print "[+] Best Practice validation results: %s : VALID" % fn
    else:
        _print_level("[!] Best Practice validation results: %s : INVALID",
                    0, fn)
        _print_level("[!] Best Practice warnings", 0)
        if 'fatal' in results:
            _print_level("[!] Fatal error occurred processing best practices: "
                        "%s", 1, results['fatal'])
            return

        warnings = results.get('warnings', {})
        root_element = warnings.get('root_element')
        if root_element:
            _print_level("[#] Root element not STIX_Package: [%s]", 1,
                        root_element['tag'])

        duplicate_ids = warnings.get('duplicate_ids')
        if duplicate_ids:
            _print_level("[#] Nodes with duplicate ids", 1)
            for id_, list_nodes in duplicate_ids.iteritems():
                _print_level("[~] id: [%s]", 2, id_)
                for node in list_nodes:
                    _print_level("[%s] line: [%s]", 3, node['tag'],
                                node['line_number'])

        missing_ids = warnings.get('missing_ids')
        if missing_ids:
            _print_level("[#] Nodes with missing ids", 1)
            for node in missing_ids:
                _print_level("[~] [%s] line: [%s]", 2, node['tag'],
                            node['line_number'])

        unresolved_idrefs = warnings.get('unresolved_idrefs')
        if unresolved_idrefs:
            _print_level("[#] Nodes with idrefs that do not resolve", 1)
            for node in unresolved_idrefs:
                _print_level("[~] [%s] idref: [%s] line: [%s]", 2, node['tag'],
                            node['idref'], node['line_number'])

        formatted_ids = warnings.get('id_format')
        if formatted_ids:
            _print_level("[#] Nodes with ids not formatted as [ns_prefix]:"
                        "[object-type]-[GUID]", 1)
            for node in formatted_ids:
                _print_level("[~] [%s] id: [%s] line: [%s]", 2, node['tag'],
                            node['id'], node['line_number'])

        idrefs_with_content = warnings.get('idref_with_content')
        if idrefs_with_content:
            _print_level("[#] Nodes that declare idrefs but also contain "
                        "content", 1)
            for node in idrefs_with_content:
                _print_level("[~] [%s] idref: [%s] line: [%s]", 2, node['tag'],
                            node['idref'], node['line_number'])

        indicator_suggestions = warnings.get('indicator_suggestions')
        if indicator_suggestions:
            _print_level("[#] Indicator suggestions", 1)
            for node in indicator_suggestions:
                _print_level("[~] id: [%s] line: [%s] missing: %s", 2,
                            node['id'], node['line_number'],
                            node.get('missing'))

        missing_titles = warnings.get('missing_titles')
        if missing_titles:
            _print_level("[#] Missing Titles", 1)
            for node in missing_titles:
                _print_level("[~] [%s] id: [%s] line: [%s]", 2,
                            node['tag'], node['id'], node['line_number'])


def _print_profile_results(fn, results):
    report = results.get('report', {})
    errors = report.get('errors')
    if not errors:
        _print_level("[+] Profile validation results: %s : VALID", 0, fn)
    else:
        _print_level("[!] Profile validation results: %s : INVALID", 0, fn)
        _print_level("[!] Profile Errors", 0)
        for error in sorted(errors, key=lambda x: x['error']):
            msg = error.get('error')
            line_numbers = error['line_numbers']
            line_numbers.sort()
            _print_level("[!] %s [%s]", 1, msg, ', '.join(line_numbers))


def _print_json_results(results):
    
    json_results = {}
    for fn, result in results.iteritems():
        d = {}
        if result.schema_results:
            d['schema_validation'] = result.schema_results
        if result.profile_results:
            d['profile_results'] = result.profile_results
        if result.best_practice_results:
            d['best_practice_results'] = result.best_practice_results

        json_results[fn] = d

    print json.dumps(json_results)


def _print_results(results, options):
    if options.json_results:
        _print_json_results(results)
        return

    for fn, result in results.iteritems():
        if result.schema_results:
            _print_schema_results(fn, result.schema_results)
        if result.best_practice_results:
            _print_best_practice_results(fn, result.best_practice_results)
        if result.profile_results:
            _print_profile_results(fn, result.profile_results)


def _convert_profile(validator, options):
    xslt = validator.get_xslt()
    schematron = validator.get_schematron()

    schematron_out_fn = options.schematron_out
    xslt_out_fn = options.xslt_out

    if schematron_out_fn:
        _info("Writing schematron conversion of profile to %s" %
             schematron_out_fn)
        schematron.write(schematron_out_fn, pretty_print=True,
                         xml_declaration=True, encoding="UTF-8")
    if xslt_out_fn:
        _info("Writing xslt conversion of profile to %s" % xslt_out_fn)
        xslt.write(xslt_out_fn, pretty_print=True, xml_declaration=True,
                   encoding="UTF-8")


def _schema_validate(validator, fn, options):
    _info("Performing xml schema validation on %s" % fn)
    results = validator.validate(fn, version=options.stix_version,
                                 schemaloc=options.use_schemaloc)
    is_valid = results['result']
    if not is_valid:
        raise SchemaInvalidError(results=results)

    return results


def _best_practice_validate(validator, fn, options):
    _info("Performing best practice validation on %s" % fn)
    results = validator.validate(fn, version=options.stix_version)
    return results


def _profile_validate(validator, fn):
    _info("Performing profile validation on %s" % fn)
    results = validator.validate(fn)
    return results


def _get_schema_validator(options):
    if options.schema_validate:
        return STIXSchemaValidator(schemas=settings.SCHEMAS)
    return None


def _get_profile_validator(options):
    if any((options.profile_validate, options.profile_convert)):
        return STIXProfileValidator(options.in_profile)
    return None


def _get_best_practice_validator(options):
    if options.best_practice_validate:
        return STIXBestPracticeValidator()
    return None


def _validate_file(fn, schema_validator, profile_validator,
              best_practice_validator, options):

    results = ValidationResults(fn)

    try:
        if schema_validator:
            results.schema_results = _schema_validate(schema_validator, fn,
                                                      options)
        if best_practice_validator:
            results.best_practice_results = \
                _best_practice_validate(best_practice_validator, fn, options)

        if profile_validator:
            results.profile_results = _profile_validate(profile_validator, fn)

    except SchemaInvalidError as ex:
        results.schema_results = ex.results
        if any((profile_validator, best_practice_validator)):
            msg = ("File %s was schema-invalid. No other validation will be "
                  "performed." % fn)
            _info(msg)

    return results


def _validate(options):
    files = _get_files_to_validate(options)
    schema_validator = _get_schema_validator(options)
    profile_validator = _get_profile_validator(options)
    best_practice_validator = _get_best_practice_validator(options)

    results = {}
    for fn in files:
        result = _validate_file(fn, schema_validator, profile_validator,
                                 best_practice_validator, options)
        results[fn] = result

    _print_results(results, options)

    if options.profile_convert:
        _convert_profile(profile_validator, options)


def _set_validation_options(args):
    options = ValidationOptions()

    if (args.files and any((settings.SCHEMAS, args.use_schemaloc))):
        options.schema_validate = True

    if options.schema_validate and args.profile:
        options.profile_validate = True

    if args.profile and any((args.schematron, args.xslt)):
        options.profile_convert = True

    # best practice options
    options.best_practice_validate = args.best_practices

    # input options
    options.stix_version = args.stix_version
    options.in_files = args.files
    options.in_profile = args.profile

    # output options
    options.xslt_out = args.xslt
    options.schematron_out = args.schematron
    options.json_results = args.json
    options.quiet_output = args.quiet

    return options


def _validate_args(args):

    schema_validate = False
    profile_validate = False
    profile_convert = False

    if len(sys.argv) == 1:
        raise ArgumentError("Invalid arguments", show_help=True)

    if (args.files and any((settings.SCHEMAS, args.use_schemaloc))):
        schema_validate = True

    if schema_validate and args.profile:
        profile_validate = True

    if args.profile and any((args.schematron, args.xslt)):
        profile_convert = True

    if all((args.stix_version, args.use_schemaloc)):
        raise ArgumentError("Cannot set both --stix-version and "
                            "--use-schemalocs")

    if any((args.xslt, args.schematron)) and not args.profile:
        raise ArgumentError("Profile filename is required when profile "
                            "conversion options are set.")

    if (args.files and not any((settings.SCHEMAS, args.use_schemaloc))):
        raise ArgumentError("Must provide either --use-schemaloc or "
                            "settings.SCHEMAS when --input-file or input-dir "
                            "declared")

    if (args.profile and not any((profile_validate, profile_convert))):
        raise ArgumentError("Profile specified but no conversion options or "
                            "validation options specified")

@Gooey(program_name ="STIX Validator") # create fancy GUI
def _get_arg_parser():
    
    parser = argparse.ArgumentParser(description="STIX Document Validator v%s"
                                    % __version__)
    parser.add_argument("--stix-version", dest="stix_version", default=None,
                        help="The version of STIX to validate against")
    parser.add_argument("--use-schemaloc", dest="use_schemaloc",
                        action='store_true', default=False, help="Use "
                        "schemaLocation attribute to determine schema "
                        "locations.")
    parser.add_argument("--best-practices", dest="best_practices",
                        action='store_true', default=False,
                        help="Check that the document follows authoring "
                        "best practices")
    parser.add_argument("--profile", dest="profile", default=None,
                        help="Path to STIX profile in excel")
    parser.add_argument("--schematron-out", dest="schematron", default=None,
                        help="Path to converted STIX profile schematron file "
                        "output.")
    parser.add_argument("--xslt-out", dest="xslt", default=None,
                        help="Path to converted STIX profile schematron xslt "
                        "output.")
    parser.add_argument("--quiet", dest="quiet", action="store_true",
                        default=False, help="Only print results and errors if "
                        "they occur.")
    parser.add_argument("--json-results", dest="json", action="store_true",
                        default=False, help="Print results as raw JSON. This "
                        "also sets --quiet.")
    parser.add_argument("files", metavar="FILES", nargs="*",
                        help="A whitespace separated list of STIX files or "
                             "directories of STIX files to validate.")

    return parser


def main():
    
    parser = _get_arg_parser()
    args = parser.parse_args()

    try:
        _validate_args(args)
        options = _set_validation_options(args)

        _set_output_level(options)
        _validate(options)
    except ArgumentError as ex:
        if ex.show_help:
            parser.print_help()
        _error(ex)
    except Exception:
        logging.exception("Fatal error occurred")
        sys.exit(EXIT_FAILURE)

if __name__ == '__main__':
    main()
