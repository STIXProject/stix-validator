#!/usr/bin/env python

# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

"""STIX Document Validator (sdv) - validates STIX instance documents.

The STIX Document Validator can perform the following forms of STIX document
validator:

* STIX XML Schema validation
* STIX Profile validation
* STIX Best Practice validation

This script uses different exit status codes to indicate various forms of
errors that can occur during validation. Because validation errors are
additive, users can bitmask the return values to determine what errors
occurred at a glance:

* ``0x0``. No errors occurred.
* ``0x1``. A fatal system error occurred.
* ``0x2``. At least one schema-invalid document was processed.
* ``0x4``. At least one profile-invalid document was processed.
* ``0x8``. At least on best-practice-invalid document was processed.
* ``0x10``. A non-fatal error occurred during validation. This usually
  indicates scenarios where malformed XML documents are validated or missing
  files are attempted to be validated.

Attributes:
    quiet: If ``True`` only validation results and fatal errors will be
        printed.

"""
import sys
import logging
import collections
import argparse
import json
import sdv
import sdv.codes as codes
import sdv.errors as errors
import sdv.utils as utils
from sdv.validators import (
    STIXSchemaValidator, STIXProfileValidator, STIXBestPracticeValidator,
    ValidationErrorResults
)

# Only print results and/or system errors.
quiet = False

class ValidationOptions(object):
    """Collection of validation options which can be set via command line.

    Attributes:
        schema_validate: True if XML Schema validation should be performed.
        schema_dir: A user-defined schema directory to validate against.
        use_schemaloc: True if the XML Schema validation process should look
            at the xsi:schemaLocation attribute to find schemas to validate
            against.
        stix_version: The version of STIX which should be validated against.
        profile_validate: True if profile validation should be performed.
        best_practice_validate: True if STIX best practice validation should
            be performed.
        profile_convert: True if a STIX Profile should be converted into
            schematron or xslt.
        xslt_out: The filename for the output profile xslt.
        schematron_out: The filename for the output profile schematron.
        json_results: True if results should be printed in JSON format.
        quiet_output: True if only results and fatal errors should be printed
            to stdout/stderr.
        in_files: A list of input files and directories of files to be
            validated.
        in_profile: A filename/path for a STIX Profile to validate against or
            convert.
        recursive: Recursively descend into input directories.

    """
    def __init__(self):
        # validation options
        self.schema_validate = False
        self.schema_dir = None
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
        self.recursive = False


class ValidationResults(object):
    """Stores validation results for given file.

    Args:
        fn: The filename/path for the file that was validated.

    Attributes:
        fn: The filename/path for the file that was validated.
        schema_results: XML schema validation results.
        best_practice_results: STIX Best Practice validation results.
        profile_resutls: STIX Profile validation results.
        fatal: Fatal error

    """
    def __init__(self, fn=None):
        self.fn = fn
        self.schema_results = None
        self.best_practice_results = None
        self.profile_results = None
        self.fatal = None


class ArgumentError(Exception):
    """An exception to be raised when invalid or incompatible arguments are
    passed into the application via the command line.

    Args:
        show_help (bool): If true, the help/usage information should be printed
            to the screen.

    Attributes:
        show_help (bool): If true, the help/usage information should be printed
            to the screen.

    """
    def __init__(self, msg=None, show_help=False):
        super(ArgumentError, self).__init__(msg)
        self.show_help = show_help


class SchemaInvalidError(Exception):
    """Exception to be raised when schema validation fails for a given
    STIX document.

    Attributes:
        results: An instance of sdv.validators.XmlValidationResults.

    """
    def __init__(self, msg=None, results=None):
        super(SchemaInvalidError, self).__init__(msg)
        self.results = results


def _error(msg, status=codes.EXIT_FAILURE):
    """Prints a message to the stderr prepended by '[!]' and calls
    ```sys.exit(status)``.

    Args:
        msg: The error message to print.
        status: The exit status code. Defaults to ``EXIT_FAILURE`` (1).

    """
    sys.stderr.write("[!] %s\n" % str(msg))
    sys.exit(status)


def _info(msg):
    """Prints a message to stdout, prepended by '[-]'.

    Note:
        If the application is running in "Quiet Mode"
        (i.e., ``quiet == True``), this function will return
        immediately and no message will be printed.

    Args:
        msg: The message to print.

    """
    if quiet:
        return

    print "[-] %s" % msg


def _print_level(fmt, level, *args):
    """Prints a formatted message to stdout prepended by spaces. Useful for
    printing hierarchical information, like bullet lists.

    Args:
        fmt (str): A Python formatted string.
        level (int): Used to determing how many spaces to print. The formula
            is ``'    ' * level ``.
        *args: Variable length list of arguments. Values are plugged into the
            format string.

    Examples:
        >>> _print_level("%s %d", 0, "TEST", 0)
        TEST 0
        >>> _print_level("%s %d", 1, "TEST", 1)
            TEST 1
        >>> _print_level("%s %d", 2, "TEST", 2)
                TEST 2

    """
    msg = fmt % args
    spaces = '    ' * level
    print "%s%s" % (spaces, msg)


def _set_output_level(options):
    """Set the output level for the application.

    If the ``quiet_output`` or ``json_results`` attributes are set on `options`
    then the application does not print informational messages to stdout; only
    results or fatal errors are printed to stdout.

    """
    global quiet
    quiet = options.quiet_output or options.json_results


def _print_fatal_results(results, level=0):
    """Prints fatal errors that occurred during validation runs."""
    _print_level("[!] Fatal Error: %s", level, results.error)


def _print_schema_results(results, level=0):
    """Prints STIX Schema validation results to stdout.

    Args:
        results: An instance of sdv.validators.XmlSchemaResults.
        level: The level to print the results.

    """
    marker = "+" if results.is_valid else "!"
    _print_level("[%s] XML Schema: %s", level, marker, results.is_valid)

    if results.is_valid:
        return

    for error in results.errors:
        _print_level("[!] %s", level+1, error)


def _print_best_practice_results(results, level=0):
    """Prints STIX Best Practice validation results to stdout.

    Args:
        results: An instance of sdv.validators.STIXBestPracticeResults
        level: The level to print the results.

    """
    def _print_warning(warning, level):
        core_keys = warning.core_keys

        # Print "core" values (e.g., id, idref, tag, etc.)
        for key in (x for x in warning if x in core_keys):
            _print_level("[-] %s : %s", level, key, warning[key])

        # Print "other" values (e.g., 'found version')
        for key in (x for x in warning if x not in core_keys):
            _print_level("[-] %s : %s", level, key, warning[key])

    def _print_warnings(collection, level):
        for warning in collection:
            _print_warning(warning, level)

            # Print a divider if not the last warning
            if warning is not collection[-1]:
                _print_level("-"*80, level)

    marker = "+" if results.is_valid else "!"
    _print_level("[%s] Best Practices: %s", level, marker, results.is_valid)

    if results.is_valid:
        return

    for collection in sorted(results, key=lambda x: x.name):
        _print_level("[!] %s", level+1, collection.name)
        _print_warnings(collection, level+2)


def _print_profile_results(results, level):
    """Prints STIX Profile validation results to stdout.

    Args:
        results: An instance of sdv.validators.STIXProfileResults.
        level: The level to print the results.

    """
    marker = "+" if results.is_valid else "!"
    _print_level("[%s] Profile: %s", level, marker, results.is_valid)

    if results.is_valid:
        return

    errors_ = collections.defaultdict(list)
    for e in results.errors:
        errors_[e.message].append(e.line)

    for msg, lines in errors_.iteritems():
        _print_level("[!] %s [%s]", level+1, msg, ', '.join(lines))


def _print_json_results(results):
    """Prints `results` to stdout in JSON format.

    Args:
        results: An instance of ``ValidationResults`` which contains the
            results to print.
    """
    json_results = {}
    for fn, result in results.iteritems():
        d = {}
        if result.schema_results is not None:
            d['schema validation'] = result.schema_results.as_dict()
        if result.profile_results is not None:
            d['profile results'] = result.profile_results.as_dict()
        if result.best_practice_results is not None:
            d['best practice results'] = result.best_practice_results.as_dict()
        if result.fatal is not None:
            d['fatal'] = result.fatal.as_dict()

        json_results[fn] = d

    print json.dumps(json_results)


def _print_results(results, options):
    """Prints `results` to stdout. If ``options.json_output`` is set, the
    results are printed in JSON format.

    Args:
        results: A dictionary of ValidationResults instances. The key is the
            file path to the validated document.
        options: An instance of ``ValidationOptions`` which contains output
            options.

    """
    if options.json_results:
        _print_json_results(results)
        return

    level = 0
    for fn, result in sorted(results.iteritems()):
        print "=" * 80
        _print_level("[-] Results: %s", level, fn)

        if result.schema_results is not None:
            _print_schema_results(result.schema_results, level)
        if result.best_practice_results is not None:
            _print_best_practice_results(result.best_practice_results, level)
        if result.profile_results is not None:
            _print_profile_results(result.profile_results, level)
        if result.fatal is not None:
            _print_fatal_results(result.fatal, level)


def _convert_profile(validator, options):
    """Converts a STIX Profile to XSLT and/or Schematron formats.

    This converts a STIX Profile document and writes the results to output
    schematron and/or xslt files to the output file names.

    The output file names are defined by
    ``output.xslt_out`` and ``options.schematron_out``.

    Args:
        validator: An instance of STIXProfileValidator
        options: ValidationOptions instance with validation options for this
            validation run.

    """
    xslt = validator.xslt
    schematron = validator.schematron

    schematron_out_fn = options.schematron_out
    xslt_out_fn = options.xslt_out

    if schematron_out_fn:
        _info(
            "Writing schematron conversion of profile to %s" %
            schematron_out_fn
        )

        schematron.write(
            schematron_out_fn,
            pretty_print=True,
            xml_declaration=True,
            encoding="UTF-8"
        )

    if xslt_out_fn:
        _info("Writing xslt conversion of profile to %s" % xslt_out_fn)
        xslt.write(
            xslt_out_fn,
            pretty_print=True,
            xml_declaration=True,
            encoding="UTF-8"
        )


def _schema_validate(validator, fn, options):
    """Performs STIX XML Schema validation against the input filename.

    Args:
        validator: An instance of validators.STIXSchemaValidator
        fn: A filename for a STIX document
        options: ValidationOptions instance with validation options for this
            validation run.

    Returns:
        A dictionary of validation results

    """
    _info("Performing xml schema validation on %s" % fn)

    results = validator.validate(
        fn, version=options.stix_version, schemaloc=options.use_schemaloc
    )

    if not results.is_valid:
        raise SchemaInvalidError(results=results)

    return results


def _best_practice_validate(validator, fn, options):
    """Performs STIX Best Practice validation against the input filename.

    Args:
        validator: An instance of STIXBestPracticeValidator
        fn: A filename for a STIX document
        options: ValidationOptions instance with validation options for
            this validation run.

    Returns:
        A dictionary of validation results

    """
    _info("Performing best practice validation on %s" % fn)
    results = validator.validate(fn, version=options.stix_version)
    return results


def _profile_validate(validator, fn):
    """Performs STIX Profile validation against the input filename.

    Args:
        fn: A filename for a STIX document

    Returns:
        A dictionary of validation results

    """
    _info("Performing profile validation on %s" % fn)
    results = validator.validate(fn)
    return results


def _get_schema_validator(options):
    """Initializes a ``STIXSchemaValidator`` instance.

    Args:
        options: An instance of ``ValidationOptions``

    Returns:
        An instance of ``STIXSchemaValidator``

    """
    if options.schema_validate:
        _info("Initializing STIX XML Schema validator")
        return STIXSchemaValidator(schema_dir=options.schema_dir)
    return None


def _get_profile_validator(options):
    """Initializes a ``STIXProfileValidator`` instance.

    Args:
        options: An instance of ``ValidationOptions``

    Returns:
        An instance of ``STIXProfileValidator``

    """
    if any((options.profile_validate, options.profile_convert)):
        _info("Initializing STIX Profile validator")
        return STIXProfileValidator(options.in_profile)
    return None


def _get_best_practice_validator(options):
    """Initializes a ``STIXBestPracticeValidator`` instance.

    Args:
        options: An instance of ``ValidationOptions``

    Returns:
        An instance of ``STIXBestPracticeValidator``

    """
    if options.best_practice_validate:
        _info("Initializing STIX Best Practice validator")
        return STIXBestPracticeValidator()
    return None


def _validate_file(fn, options, schema_validator=None, profile_validator=None,
                   best_practice_validator=None):
    """Validates the input document `fn` with the validators that are passed
    in.

    Profile and/or Best Practice validation will only occur if `fn` is
    schema-valid.

    If any exceptions are raised during validation, no further validation
    will take place.

    Args:
        schema_validator: An instance of STIXSchemaValidator (optional)
        profile_validator: An instance of STIXProfileValidator (optional)
        best_practice_validator: An instance of STIXBestPracticeValidator
            (optional).
        options: An instance of ValidationOptions.

    Returns:
        An instance of ValidationResults.

    """
    results = ValidationResults(fn)

    try:
        if schema_validator:
            results.schema_results = _schema_validate(
                schema_validator, fn, options
            )

        if best_practice_validator:
            results.best_practice_results = _best_practice_validate(
                best_practice_validator, fn, options
            )

        if profile_validator:
            results.profile_results = _profile_validate(profile_validator, fn)

    except SchemaInvalidError as ex:
        results.schema_results = ex.results
        if any((profile_validator, best_practice_validator)):
            msg = (
                "File %s was schema-invalid. No further validation will be "
                "performed." % fn
            )
            _info(msg)
    except Exception as ex:
        results.fatal = ValidationErrorResults(ex)
        _info("Unexpected error occurred with file %s. No further validation "
              "will be performed: %s" % (fn, str(ex)))

    return results


def _validate(options):
    """Validates files based on command line options.

    Args:
        options: An instance of ``ValidationOptions`` containing options for
            this validation run.

    """
    files = utils.get_xml_files(options.in_files, options.recursive)
    schema_validator = _get_schema_validator(options)
    profile_validator = _get_profile_validator(options)
    best_practice_validator = _get_best_practice_validator(options)

    results = {}
    for fn in files:
        result = _validate_file(
            fn,
            options,
            schema_validator=schema_validator,
            profile_validator=profile_validator,
            best_practice_validator=best_practice_validator
        )
        results[fn] = result

    if options.profile_convert:
        _convert_profile(profile_validator, options)

    return results


def _set_validation_options(args):
    """Populates an instance of ``ValidationOptions`` from the `args` param.

    Args:
        args (argparse.Namespace): The arguments parsed and returned from
            ArgumentParser.parse_args().

    Returns:
        Instance of ``ValidationOptions``.

    """
    options = ValidationOptions()

    if (args.files):
        options.schema_validate = True

    if options.schema_validate and args.profile:
        options.profile_validate = True

    if args.profile and any((args.schematron, args.xslt)):
        options.profile_convert = True

    # best practice options
    options.best_practice_validate = args.best_practices

    # input options
    options.stix_version = args.stix_version
    options.schema_dir = args.schema_dir
    options.in_files = args.files
    options.in_profile = args.profile
    options.recursive = args.recursive

    # output options
    options.xslt_out = args.xslt
    options.schematron_out = args.schematron
    options.json_results = args.json
    options.quiet_output = args.quiet

    return options


def _validate_args(args):
    """Checks that valid and compatible command line arguments were passed into
    the application.

    Args:
        args (argparse.Namespace): The arguments parsed and returned from
            ArgumentParser.parse_args().

    Raises:
        ArgumentError: If invalid or incompatible command line arguments were
            passed into the application.

    """
    schema_validate = False
    profile_validate = False
    profile_convert = False

    if len(sys.argv) == 1:
        raise ArgumentError("Invalid arguments", show_help=True)

    if (args.files):
        schema_validate = True

    if schema_validate and args.profile:
        profile_validate = True

    if args.profile and any((args.schematron, args.xslt)):
        profile_convert = True

    if all((args.stix_version, args.use_schemaloc)):
        raise ArgumentError(
            "Cannot set both --stix-version and --use-schemalocs"
        )

    if any((args.xslt, args.schematron)) and not args.profile:
        raise ArgumentError(
            "Profile filename is required when profile conversion options "
            "are set."
        )

    if (args.profile and not any((profile_validate, profile_convert))):
        raise ArgumentError(
            "Profile specified but no conversion options or validation "
            "options specified."
        )


def _get_arg_parser():
    """Initializes and returns an argparse.ArgumentParser instance for this
    application.

    Returns:
        Instance of ``argparse.ArgumentParser``

    """
    parser = argparse.ArgumentParser(
        description="STIX Document Validator v%s" % sdv.__version__
    )

    parser.add_argument(
        "--stix-version",
        dest="stix_version",
        default=None,
        help="The version of STIX to validate against"
    )

    parser.add_argument(
        "--schema-dir",
        dest="schema_dir",
        default=None,
        help="Schema directory. If not provided, the STIX schemas bundled "
             "with the stix-validator library will be used."
    )

    parser.add_argument(
        "--use-schemaloc",
        dest="use_schemaloc",
        action='store_true',
        default=False,
        help="Use schemaLocation attribute to determine schema locations."
    )

    parser.add_argument(
        "--best-practices",
        dest="best_practices",
        action='store_true',
        default=False,
        help="Check that the document follows authoring best practices."
    )

    parser.add_argument(
        "--profile",
        dest="profile",
        default=None,
        help="Path to STIX Profile .xlsx file."
    )

    parser.add_argument(
        "--schematron-out",
        dest="schematron",
        default=None,
        help="Path to converted STIX profile schematron file output."
    )

    parser.add_argument(
        "--xslt-out",
        dest="xslt",
        default=None,
        help="Path to converted STIX profile schematron xslt output."
    )

    parser.add_argument(
        "--quiet",
        dest="quiet",
        action="store_true",
        default=False,
        help="Only print results and errors if they occur."
    )

    parser.add_argument(
        "--json-results",
        dest="json",
        action="store_true",
        default=False,
        help="Print results as raw JSON. This also sets --quiet."
    )

    parser.add_argument(
        "--recursive",
        dest="recursive",
        action="store_true",
        default=False,
        help="Recursively descend into input directories."
    )

    parser.add_argument(
        "files",
        metavar="FILES",
        nargs="*",
        help="A whitespace separated list of STIX files or directories of "
             "STIX files to validate."
    )

    return parser


def _status_code(results):
    """Determines the exit status code to be returned from this script
    by inspecting the results returned from validating file(s).

    Status codes are binary OR'd together, so exit codes can communicate
    multiple error conditions.

    """
    status = codes.EXIT_SUCCESS

    for result in results.itervalues():
        schema = result.schema_results
        best_practice = result.best_practice_results
        profile = result.profile_results
        fatal = result.fatal

        if schema and not schema.is_valid:
            status |= codes.EXIT_SCHEMA_INVALID
        if best_practice and not best_practice.is_valid:
            status |= codes.EXIT_BEST_PRACTICE_INVALID
        if profile and not profile.is_valid:
            status |= codes.EXIT_PROFILE_INVALID
        if fatal:
            status |= codes.EXIT_VALIDATION_ERROR

    sys.exit(status)


def main():
    """Entry point for sdv.py.

    Parses and validates command line arguments and then does at least one of
    the following:

    * Validates instance document against schema/best practices/profile and
      prints results to stdout.
    * Converts a STIX profile into xslt and/or schematron formats
    * Prints an error to stderr and exit(1)

    """
    parser = _get_arg_parser()
    args = parser.parse_args()

    try:
        # Validate the input command line arguments
        _validate_args(args)

        # Parse the input options
        options = _set_validation_options(args)

        # Set the output level (e.g., quiet vs. verbose)
        _set_output_level(options)

        # Validate input documents
        results = _validate(options)

        # Print validation results
        _print_results(results, options)

        # Determine exit status code and exit.
        code = _status_code(results)
        sys.exit(code)

    except ArgumentError as ex:
        if ex.show_help:
            parser.print_help()
        _error(ex)
    except (errors.ValidationError, IOError) as ex:
        _error(
            "Validation error occurred: '%s'" % str(ex),
            codes.EXIT_VALIDATION_ERROR
        )
    except Exception:
        logging.exception("Fatal error occurred")
        sys.exit(codes.EXIT_FAILURE)

if __name__ == '__main__':
    main()
