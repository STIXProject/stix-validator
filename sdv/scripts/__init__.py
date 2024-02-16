# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import sys
import json
import collections

# external
import lxml.etree

# internal
import sdv
import sdv.codes as codes
import sdv.utils as utils
import sdv.validators.base as base

_QUIET = False

class ValidationOptions(object):
    """Collection of validation options which can be set via command line.

    Attributes:
        schema_validate: True if XML Schema validation should be performed.
        schema_dir: A user-defined schema directory to validate against.
        use_schemaloc: True if the XML Schema validation process should look
            at the xsi:schemaLocation attribute to find schemas to validate
            against.
        lang_version: The version of STIX/CybOX which should be validated
            against.
        profile_validate: True if profile validation should be performed.
        best_practice_validate: True if STIX best practice validation should
            be performed.
        json_results: True if results should be printed in JSON format.
        quiet_output: True if only results and fatal errors should be printed
            to stdout/stderr.
        in_files: A list of input files and directories of files to be
            validated.
        in_profile: A filename/path for a STIX Profile to validate against.
        recursive: Recursively descend into input directories.

    """
    def __init__(self):
        # validation options
        self.schema_validate = False
        self.schema_dir = None
        self.use_schemaloc = False
        self.lang_version = None
        self.profile_validate = False
        self.best_practice_validate = False

        # Classes
        self.xml_validation_class = None
        self.best_practice_validation_class = None
        self.profile_validation_class = None

        # output options
        self.json_results = False
        self.quiet_output = False

        # input options
        self.in_files = None
        self.in_profile = None
        self.recursive = False
        self.huge_tree = False


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


class ValidationErrorResults(base.ValidationResults):
    """Can be used to communicate a failed validation due to a raised Exception.

    Args:
        error: An ``Exception`` instance raised by validation code.

    Attributes:
        is_valid: Always ``False``.
        error: The string representation of the Exception being passed in.
        exception: The exception which produced these results.

    """
    def __init__(self, error):
        self._is_valid = False
        self.error = str(error)
        self.exception = error

    def as_dict(self):
        d = super(ValidationErrorResults, self).as_dict()
        d['error'] = self.error

        return d


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


def set_output_level(options):
    """Set the output level for the application.

    If the ``quiet_output`` or ``json_results`` attributes are set on `options`
    then the application does not print informational messages to stdout; only
    results or fatal errors are printed to stdout.

    """
    global _QUIET
    _QUIET = options.quiet_output or options.json_results


def error(msg, status=codes.EXIT_FAILURE):
    """Prints a message to the stderr prepended by '[!]' and calls
    ```sys.exit(status)``.

    Args:
        msg: The error message to print.
        status: The exit status code. Defaults to ``EXIT_FAILURE`` (1).

    """
    sys.stderr.write("[!] %s\n" % str(msg))
    sys.exit(status)


def info(msg):
    """Prints a message to stdout, prepended by '[-]'.

    Note:
        If the application is running in "Quiet Mode"
        (i.e., ``_QUIET == True``), this function will return
        immediately and no message will be printed.

    Args:
        msg: The message to print.

    """
    if _QUIET:
        return

    print("[-] %s" % msg)


def print_level(fmt, level, *args):
    """Prints a formatted message to stdout prepended by spaces. Useful for
    printing hierarchical information, like bullet lists.

    Args:
        fmt (str): A Python formatted string.
        level (int): Used to determing how many spaces to print. The formula
            is ``'    ' * level ``.
        *args: Variable length list of arguments. Values are plugged into the
            format string.

    Examples:
        >>> print_level("%s %d", 0, "TEST", 0)
        TEST 0
        >>> print_level("%s %d", 1, "TEST", 1)
            TEST 1
        >>> print_level("%s %d", 2, "TEST", 2)
                TEST 2

    """
    msg = fmt % args
    spaces = '    ' * level
    print("%s%s" % (spaces, msg))


def print_fatal_results(results, level=0):
    """Prints fatal errors that occurred during validation runs."""
    print_level("[!] Fatal Error: %s", level, results.error)


def print_schema_results(results, level=0):
    """Prints XML Schema validation results to stdout.

    Args:
        results: An instance of sdv.validators.XmlSchemaResults.
        level: The level to print the results.

    """
    marker = "+" if results.is_valid else "!"
    print_level("[%s] XML Schema: %s", level, marker, results.is_valid)

    if results.is_valid:
        return

    for error in results.errors:
        print_level("[!] %s", level+1, error)


def print_best_practice_results(results, level=0):
    """Prints STIX Best Practice validation results to stdout.

    Args:
        results: An instance of sdv.validators.STIXBestPracticeResults
        level: The level to print the results.

    """
    def print_warning(warning, level):
        core_keys = warning.core_keys

        # Print "core" values (e.g., id, idref, tag, etc.)
        for key in (x for x in warning if x in core_keys):
            print_level("[-] %s : %s", level, key, warning[key])

        # Print "other" values (e.g., 'found version')
        for key in (x for x in warning if x not in core_keys):
            print_level("[-] %s : %s", level, key, warning[key])

    def print_warnings(collection, level):
        for warning in collection:
            print_warning(warning, level)

            # Print a divider if not the last warning
            if warning is not collection[-1]:
                print_level("-"*80, level)

    marker = "+" if results.is_valid else "!"
    print_level("[%s] Best Practices: %s", level, marker, results.is_valid)

    if results.is_valid:
        return

    for collection in sorted(results, key=lambda x: x.name):
        print_level("[!] %s", level+1, collection.name)
        print_warnings(collection, level+2)


def print_profile_results(results, level):
    """Prints STIX Profile validation results to stdout.

    Args:
        results: An instance of sdv.validators.STIXProfileResults.
        level: The level to print the results.

    """
    marker = "+" if results.is_valid else "!"
    print_level("[%s] Profile: %s", level, marker, results.is_valid)

    if results.is_valid:
        return

    errors_ = collections.defaultdict(list)
    for e in results.errors:
        errors_[e.message].append(e.line)

    for msg, lines in errors_.items():
        lines = ', '.join(str(x) for x in lines)
        print_level("[!] %s [%s]", level+1, msg, lines)


def print_json_results(results):
    """Prints `results` to stdout in JSON format.

    Args:
        results: An instance of ``ValidationResults`` which contains the
            results to print.
    """
    json_results = {}
    for fn, result in results.items():
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

    print(json.dumps(json_results))


def print_results(results, options):
    """Prints `results` to stdout. If ``options.json_output`` is set, the
    results are printed in JSON format.

    Args:
        results: A dictionary of ValidationResults instances. The key is the
            file path to the validated document.
        options: An instance of ``ValidationOptions`` which contains output
            options.

    """
    if options.json_results:
        print_json_results(results)
        return

    level = 0
    for fn, result in sorted(results.items()):
        print("=" * 80)
        print_level("[-] Results: %s", level, fn)

        if result.schema_results is not None:
            print_schema_results(result.schema_results, level)
        if result.best_practice_results is not None:
            print_best_practice_results(result.best_practice_results, level)
        if result.profile_results is not None:
            print_profile_results(result.profile_results, level)
        if result.fatal is not None:
            print_fatal_results(result.fatal, level)


def profile_validate(fn, options):
    """Performs STIX Profile validation against the input filename.
    Args:
        fn: A filename for a STIX document
    Returns:
        A dictionary of validation results
    """
    info("Performing profile validation on %s" % fn)

    results = sdv.validate_profile(
        fn,
        profile=options.in_profile
    )

    return results


def schema_validate(fn, options):
    """Performs STIX/CybOX XML Schema validation against the input filename.

    Args:
        fn: A filename for a STIX/CybOX XML document
        options: ValidationOptions instance with validation options for this
            validation run.

    Returns:
        A dictionary of validation results

    """
    info("Performing xml schema validation on %s" % fn)

    results = sdv.validate_xml(
        fn,
        version=options.lang_version,
        schemas=options.schema_dir,
        schemaloc=options.use_schemaloc,
        klass=options.xml_validation_class
    )

    if not results.is_valid:
        raise SchemaInvalidError(results=results)

    return results


def best_practice_validate(fn, options):
    """Performs STIX Best Practice validation against the input filename.

    Args:
        validator: An instance of STIXBestPracticeValidator
        fn: A filename for a STIX document
        options: ValidationOptions instance with validation options for
            this validation run.

    Returns:
        A dictionary of validation results

    """
    info("Performing best practice validation on %s" % fn)

    results = sdv.validate_best_practices(
        doc=fn,
        version=options.lang_version
    )

    return results


def validate_file(fn, options):
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
        if options.schema_validate:
            results.schema_results = schema_validate(fn, options)
        if options.best_practice_validate:
            results.best_practice_results = best_practice_validate(fn, options)
        if options.profile_validate:
            results.profile_results = profile_validate(fn, options)
    except SchemaInvalidError as ex:
        results.schema_results = ex.results
        if options.profile_validate or options.best_practice_validate:
            msg = ("File '{fn}' was schema-invalid. No further validation will "
                   "be performed.")
            info(msg.format(fn=fn))
    except Exception as ex:
        results.fatal = ValidationErrorResults(ex)
        msg = ("Unexpected error occurred with file '{fn}'. No further "
               "validation will be performed: {error}")
        info(msg.format(fn=fn, error=str(ex)))

    return results


def _set_huge_tree_parser():
    parser = lxml.etree.ETCompatXMLParser(
        attribute_defaults=False,
        load_dtd=False,
        huge_tree=True,
        no_network=True,
        ns_clean=True,
        recover=False,
        remove_pis=False,
        remove_blank_text=False,
        remove_comments=False,
        resolve_entities=False,
        strip_cdata=True
    )

    utils.set_xml_parser(parser)


def run_validation(options):
    """Validates files based on command line options.

    Args:
        options: An instance of ``ValidationOptions`` containing options for
            this validation run.

    """
    if options.huge_tree:
        _set_huge_tree_parser()

    # The XML files to validate
    files = utils.get_xml_files(options.in_files, options.recursive)

    results = {}
    for fn in files:
        results[fn] = validate_file(fn, options)

    return results


def status_code(results):
    """Determines the exit status code to be returned from this script
    by inspecting the results returned from validating file(s).

    Status codes are binary OR'd together, so exit codes can communicate
    multiple error conditions.

    """
    status = codes.EXIT_SUCCESS

    for result in results.values():
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

    return status
