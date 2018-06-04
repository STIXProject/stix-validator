#!/usr/bin/env python

# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

"""
STIX profile to Schematron
This script takes a STIX profile, converts it to Schematron, then prints to stdout
"""

import sys
import logging
import argparse

import sdv
import sdv.codes as codes
import sdv.scripts as scripts


def _convert_profile(options):
    # Converts a STIX Profile Schematron format and prints to stdout.

    profile = options.in_profile

    schematron = sdv.profile_to_schematron(profile)
    schematron.write(
        sys.stdout,
        pretty_print=True,
        xml_declaration=True,
        encoding="UTF-8"
    )


def _get_arg_parser():
    """Initializes and returns an argparse.ArgumentParser instance for this
    application.

    Returns:
        Instance of ``argparse.ArgumentParser``

    """
    parser = argparse.ArgumentParser(
        description="STIX Profile to Schematron v%s" % sdv.__version__
    )

    parser.add_argument(
        "profile",
        help="STIX Profile filename to be converted to Schematron."
    )

    return parser


def main():
    # Main for profile-to-sch.py
    parser = _get_arg_parser()
    args = parser.parse_args()

    try:
        # Assume valid XML, prep profile for conversion
        options = scripts.ValidationOptions()
        options.in_profile = args.profile

        # Convert the profile
        _convert_profile(options)

        # If no exception was thrown, then conversion was successful.
        sys.exit(codes.EXIT_SUCCESS)

    except scripts.ArgumentError as ex:
        if ex.show_help:
            parser.print_help()
        scripts.error(ex)
    except Exception:
        logging.exception("Fatal error occurred")
        sys.exit(codes.EXIT_FAILURE)


if __name__ == '__main__':
    main()
