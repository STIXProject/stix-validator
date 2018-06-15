#!/usr/bin/env python

# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

"""STIX Document Validator - validates STIX instance documents.

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
import argparse

import sdv
import sdv.codes as codes
import sdv.errors as errors
import sdv.scripts as scripts
import sdv.validators as validators


def _set_validation_options(args):
    """Populates an instance of ``ValidationOptions`` from the `args` param.

    Args:
        args (argparse.Namespace): The arguments parsed and returned from
            ArgumentParser.parse_args().

    Returns:
        Instance of ``ValidationOptions``.

    """
    options = scripts.ValidationOptions()

    if (args.files):
        options.schema_validate = True

    if options.schema_validate and args.profile:
        options.profile_validate = True

    # best practice options
    options.best_practice_validate = args.best_practices

    # input options
    options.lang_version = args.lang_version
    options.schema_dir = args.schema_dir
    options.in_files = args.files
    options.in_profile = args.profile
    options.recursive = args.recursive
    options.use_schemaloc = args.use_schemaloc
    options.huge_tree = args.huge_tree

    # output options
    options.json_results = args.json
    options.quiet_output = args.quiet

    # validation class options
    options.xml_validation_class = validators.STIXSchemaValidator

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

    if len(sys.argv) == 1:
        raise scripts.ArgumentError("Invalid arguments", show_help=True)

    if (args.files):
        schema_validate = True

    if schema_validate and args.profile:
        profile_validate = True

    if all((args.lang_version, args.use_schemaloc)):
        raise scripts.ArgumentError(
            "Cannot set both --stix-version and --use-schemalocs"
        )

    if args.profile and not profile_validate:
        raise scripts.ArgumentError(
            "Profile specified but no validation options specified."
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
        dest="lang_version",
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
        "--huge-tree",
        dest="huge_tree",
        action="store_true",
        default=False,
        help="Disable libxml2 security restrictions on XML document size."
    )

    parser.add_argument(
        "files",
        metavar="FILES",
        nargs="*",
        help="A whitespace separated list of STIX files or directories of "
             "STIX files to validate."
    )

    return parser


def main():
    """Entry point for sdv.py.

    Parses and validates command line arguments and then does at least one of
    the following:

    * Validates instance document against schema/best practices/profile and
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
        scripts.set_output_level(options)

        # Validate input documents
        results = scripts.run_validation(options)

        # Print validation results
        scripts.print_results(results, options)

        # Determine exit status code and exit.
        code = scripts.status_code(results)
        sys.exit(code)

    except scripts.ArgumentError as ex:
        if ex.show_help:
            parser.print_help()
        scripts.error(ex)
    except (errors.ValidationError, IOError) as ex:
        scripts.error(
            "Validation error occurred: '%s'" % str(ex),
            codes.EXIT_VALIDATION_ERROR
        )
    except Exception:
        logging.exception("Fatal error occurred")
        sys.exit(codes.EXIT_FAILURE)


if __name__ == '__main__':
    main()
