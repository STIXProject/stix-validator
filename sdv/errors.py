# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.


class ValidationError(Exception):
    """Base Exception for all validator-specific exceptions. This is used
    directly by some modules as a generic Exception.

    """
    pass


class UnknownNamespaceError(ValidationError):
    """Raised when an unknown namespace is encountered in a function.

    """
    pass


class UnknownVocabularyError(ValidationError):
    """Raised when an unknown controlled vocabulary name is discovered
    during best practice validation.

    """
    pass


class IdrefLookupError(ValidationError):
    """Raised when an attempt to resolve an ID reference fails. This can
    occur when the full STIX component definition resides outside of the
    input document.

    """
    def __init__(self, idref, message=None):
        super(IdrefLookupError, self).__init__(message)
        self.idref = idref


class XMLSchemaIncludeError(ValidationError):
    """Raised when errors occur during the processing of ``xs:include``
    directives found within schema documents.

    """
    pass


class XMLSchemaImportError(ValidationError):
    """Raised when errors occur when generating ``xs:import`` directives for
    the "uber" schema, used to validate XML instance documents.

    """
    pass


class UnknownVersionError(ValidationError):
    """Base Exception for errors raised as a result of not being able to
    determine the version of an input document.

    """
    pass


class InvalidVersionError(ValidationError):
    """Base Exception for errors raised as a result of invalid version
    information being declared for a document, or found within a document.

    """
    def __init__(self, message, expected=None, found=None):
        super(InvalidVersionError, self).__init__(message)
        self.expected = expected
        self.found = found


class UnknownSTIXVersionError(UnknownVersionError):
    """Raised when no STIX version information can be found in an instance
    document and no version information was provided to a method which
    requires version information.

    """
    pass


class InvalidSTIXVersionError(InvalidVersionError):
    """Raised when an invalid version of STIX is discovered within an instance
    document or is passed into a method which depends on STIX version
    information.

    Args:
        message: The error message.
        expected: A version or list of expected versions.
        found: The STIX version that was declared for an instance document or
            found within an instance document.

    """
    pass


class UnknownCyboxVersionError(UnknownVersionError):
    """Raised when no CybOX version information can be found in an instance
    document and no version information was provided to a method which
    requires version information.

    """
    pass


class InvalidCyboxVersionError(InvalidVersionError):
    """Raised when an invalid version of CybOX is discovered within an instance
    document or is passed into a method which depends on CybOX version
    information.

    Args:
        message: The error message.
        expected: A version or list of expected versions.
        found: The CybOX version that was declared for an instance document or
            found within an instance document.

    """
    pass


class ProfileParseError(ValidationError):
    """Raised when an error occurs during the parse or initialization
    of a STIX profile document.

    """
    pass
