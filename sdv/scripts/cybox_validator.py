#!/usr/bin/env python

# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

"""CybOX Document Validator - validates CybOX XML instance documents.

This script uses different exit status codes to indicate various forms of
errors that can occur during validation. Because validation errors are
additive, users can bitmask the return values to determine what errors
occurred at a glance:

* ``0x0``. No errors occurred.
* ``0x1``. A fatal system error occurred.
* ``0x2``. At least one schema-invalid document was processed.
* ``0x10``. A non-fatal error occurred during validation. This usually
  indicates scenarios where malformed XML documents are validated or missing
  files are attempted to be validated.

Attributes:
    quiet: If ``True`` only validation results and fatal errors will be
        printed.

"""
import sys
import json
import logging
import argparse

import sdv
import sdv.codes as codes
import sdv.utils as utils
import sdv.errors as errors
import sdv.validators as validators

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
        cybox_version: The version of CybOX which should be validated against.
        json_results: True if results should be printed in JSON format.
        quiet_output: True if only results and fatal errors should be printed
            to stdout/stderr.
        in_files: A list of input files and directories of files to be
            validated.
        recursive: Recursively descend into input directories.

    """
    def __init__(self):
        # validation options
        self.schema_validate = False
        self.schema_dir = None
        self.use_schemaloc = False
        self.cybox_version = None

        # output options
        self.json_results = False
        self.quiet_output = False

        # input options
        self.in_files = None
        self.recursive = False


class ValidationResults(object):
    """Stores validation results for given file.

    Args:
        fn: The filename/path for the file that was validated.

    Attributes:
        fn: The filename/path for the file that was validated.
        schema_results: XML schema validation results.
        fatal: Fatal error

    """
    def __init__(self, fn=None):
        self.fn = fn
        self.schema_results = None
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
    CybOX document.

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
    """Prints CybOX Schema validation results to stdout.

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
        if result.fatal is not None:
            _print_fatal_results(result.fatal, level)


def _schema_validate(validator, fn, options):
    """Performs CybOX XML Schema validation against the input filename.

    Args:
        validator: An instance of validators.CybOXSchemaValidator
        fn: A filename for a CybOX document
        options: ValidationOptions instance with validation options for this
            validation run.

    Returns:
        A dictionary of validation results

    """
    _info("Performing xml schema validation on %s" % fn)

    results = validator.validate(
        fn,
        version=options.cybox_version,
        schemaloc=options.use_schemaloc
    )

    if not results.is_valid:
        raise SchemaInvalidError(results=results)

    return results


def _validate_file(fn, options, schema_validator):
    """Validates the input document `fn` with the validators that are passed
    in.

    If any exceptions are raised during validation, no further validation
    will take place.

    Args:
        schema_validator: An instance of CybOXSchemaValidator (optional)
        options: An instance of ValidationOptions.

    Returns:
        An instance of ValidationResults.

    """
    results = ValidationResults(fn)

    try:
        results.schema_results = _schema_validate(schema_validator, fn, options)
    except SchemaInvalidError as ex:
        results.schema_results = ex.results
    except Exception as ex:
        results.fatal = validators.ValidationErrorResults(ex)
        _info("Unexpected error occurred with file %s: %s" % (fn, str(ex)))

    return results


def _validate(options):
    """Validates files based on command line options.

    Args:
        options: An instance of ``ValidationOptions`` containing options for
            this validation run.

    """
    files = utils.get_xml_files(options.in_files, options.recursive)
    schema_validator = validators.CyboxSchemaValidator(schema_dir=options.schema_dir)

    results = {}
    for fn in files:
        result = _validate_file(fn, options, schema_validator=schema_validator)
        results[fn] = result

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

    # input options
    options.cybox_version = args.cybox_version
    options.schema_dir = args.schema_dir
    options.in_files = args.files
    options.recursive = args.recursive

    # output options
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
    if len(sys.argv) == 1:
        raise ArgumentError("Invalid arguments", show_help=True)

    if args.cybox_version and args.use_schemaloc:
        raise ArgumentError(
            "Cannot set both --cybox-version and --use-schemalocs"
        )


def _get_arg_parser():
    """Initializes and returns an argparse.ArgumentParser instance for this
    application.

    Returns:
        Instance of ``argparse.ArgumentParser``

    """
    parser = argparse.ArgumentParser(
        description="CybOX Document Validator v%s" % sdv.__version__
    )

    parser.add_argument(
        "--cybox-version",
        dest="cybox_version",
        default=None,
        help="The version of CybOX to validate against"
    )

    parser.add_argument(
        "--schema-dir",
        dest="schema_dir",
        default=None,
        help="Schema directory. If not provided, the CybOX schemas bundled "
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
        help="A whitespace separated list of CybOX files or directories of "
             "CybOX files to validate."
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
        fatal = result.fatal

        if schema and not schema.is_valid:
            status |= codes.EXIT_SCHEMA_INVALID
        if fatal:
            status |= codes.EXIT_VALIDATION_ERROR

    sys.exit(status)


def main():
    """Entry point for sdv.py.

    Parses and validates command line arguments and then does at least one of
    the following:

    * Validates instance document against schemas and
      prints results to stdout.
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
