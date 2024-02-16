# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# stdlib
import abc
import json

# internal
from .. import utils


class ValidationError(object):
    """Base class for validation error types."""
    def __init__(self):
        pass

    def as_dict(self):
        raise NotImplementedError()

    def as_json(self):
        """Returns a JSON representation of this class instance."""
        return json.dumps(self.as_dict())


class ValidationResults(object):
    """Base class for all validation result types."""

    def __init__(self, is_valid=False):
        self.is_valid = is_valid

    @property
    def is_valid(self):
        """Returns ``True`` if the validation attempt was successful and
        ``False`` otherwise.

        """
        return self._is_valid

    @is_valid.setter
    def is_valid(self, value):
        self._is_valid = bool(value)

    def as_dict(self):
        """Returns a dictionary representation of this class.

        Keys:
            ``'result'``: The validation result. Values will be ``True`` or
            ``False``.

        """
        return {'result': self.is_valid}

    def as_json(self):
        """Returns a JSON representation of this class instance."""
        return json.dumps(self.as_dict())


class BaseSchemaValidator(object):
    """Abstract base class for language-specific XML Schema validator classes.
    E.g., STIXSchemaValidator and CyboxSchemaValidator.

    """
    __metaclass__ = abc.ABCMeta

    _KEY_SCHEMALOC = 'schemaloc'
    _KEY_USER_DEFINED = 'user'
    _SCHEMAS = None  # Overidden by subclass

    def __init__(self, schema_dir=None):
        self._xml_validators = self._get_validators(schema_dir)
        self._is_user_defined = bool(schema_dir)

    @abc.abstractmethod
    def _raise_invalid_version(self, version):
        raise NotImplementedError()

    @abc.abstractmethod
    def _get_document_version(self, doc):
        raise NotImplementedError()

    @abc.abstractmethod
    def _get_validator_impl(self, schema_dir=None):
        raise NotImplementedError()

    def _get_validators(self, schema_dir=None):
        validators = {self._KEY_SCHEMALOC: self._get_validator_impl()}

        if schema_dir:
            validators = {
                self._KEY_USER_DEFINED: self._get_validator_impl(schema_dir)
            }
        else:
            for version, location in self._SCHEMAS.items():
                validator = self._get_validator_impl(location)
                validators[version] = validator

        return validators

    def _get_versioned_validator(self, version):
        try:
            return self._xml_validators[version]
        except KeyError:
            self._raise_invalid_version(version)

    def _validate(self, doc, version=None, schemaloc=False):
        """Performs XML Schema validation against an XML instance document.

        When validating against the set of bundled schemas, a document version
        number must be declared for the input `doc`. If a user does not pass in
        a `version` parameter, an attempt will be made to collect the version
        from the input `doc`.

        Note:
            If `schemaloc` is ``True`` or this class was initialized with a
            ``schema_dir``, no version checking or verification will occur.

        Args:
            doc: The XML document. This can be a filename, file-like object,
                ``etree._Element``, or ``etree._ElementTree`` instance.
            version: The version of the XML document. If ``None`` an attempt
                will be made to extract the version from `doc`.
            schemaloc: If ``True``, the ``xsi:schemaLocation`` attribute on
                `doc` will be used to drive the validation.

        Returns:
            An instance of
            :class:`.XmlValidationResults`.

        """
        root = utils.get_etree_root(doc)

        if schemaloc:
            validator = self._xml_validators[self._KEY_SCHEMALOC]
        elif self._is_user_defined:
            validator = self._xml_validators[self._KEY_USER_DEFINED]
        else:
            version = version or self._get_document_version(root)
            validator = self._get_versioned_validator(version)

        results = validator.validate(root, schemaloc)
        return results


__all__ = [
    'ValidationError',
    'ValidationResults',
    'BaseSchemaValidator'
]
