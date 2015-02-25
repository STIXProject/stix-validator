XML Schema Validation
=====================

The **stix-validator** library provides methods and data types to help perform
STIX and CybOX XML Schema validation. The **stix-validator** library bundles
all versions of STIX and CybOX XML Schema files with it, but also supports the
ability to validate validate against external directories of schemas or
remote, web-accessible schema locations.

The following code examples demonstrate different ways you can utilize the
STIX and CyOX XML Schema validation capabilities in **stix-validator**.

.. contents::
    :depth: 2

Validating STIX and CybOX Documents
-----------------------------------

The **stix-validator** :meth:`sdv.validate_xml` method can be used to validate
STIX and CybOX XML files or file-like objects.

.. code-block:: python

    import sdv

    # Validate the 'xml-content.xml' STIX/CybOX document using bundled XML schemas.
    results = sdv.validate_xml('xml-content.xml')

    # Print the result!
    print results.is_valid

When validating STIX content, The :meth:`sdv.validate_xml` method acts as a
proxy to the :class:`.STIXSchemaValidator` class and is equivalent to the
following:

.. code-block:: python

    from sdv.validators import STIXSchemaValidator

    # Create the validator instance
    validator = STIXSchemaValidator()

    # Validate 'xml-content.xml` STIX document using bundled STIX schemas
    results = validator.validate('xml-content.xml')

    # Print the results!
    print results.is_valid


When validating CybOX content, the :meth:`sdv.validate_xml` method passes its
input to the :class:`.CyboxSchemaValidator` class.

The examples above pass the ``'xml-content.xml'`` filename into
:meth:`sdv.validate_xml` and :meth:`.STIXSchemaValidator.validate`, but these
methods (and all other validation methods) can also accept file-like objects
(such as files on disk or ``StringIO`` instances), ``etree._Element``
instances, or ``etree._ElementTree`` instances. Super duper neato!


Using Non-bundled Schemas
-------------------------

Some STIX data which utilizes STIX extensions may require non-STIX schemas
(e.g, `OVAL`_, `OpenIOC`_, etc.) to perform validation. To validate a STIX
document which includes non-STIX extension data users can provide a path to a
directory containing all the schemas required for validation.

.. _OVAL: http://oval.mitre.org
.. _OpenIOC: http://openioc.org

.. code-block:: python

    import sdv

    # Path to a directory containing ALL schema files required for validation
    SCHEMA_DIR = "/path/to/schemas/"

    # Use the `schemas` parameter to use non-bundled schemas.
    results = sdv.validate_xml('stix-content.xml', schemas=SCHEMA_DIR)

.. note::

    Validating against external schema directories requires that **all**
    schemas necessary for validation be found under the directory. This
    includes STIX schemas!

Using ``xsi:schemaLocation``
----------------------------

XML content that contains an ``xsi:schemaLocation`` attribute referring to
external schemas can be validated using the ``xsi:schemaLocation`` value
by making use of the ``schemaloc`` parameter,

.. code-block:: python

    import sdv

    # Use the xsi:schemaLocation attribute to resolve remote schemas
    results = sdv.validate_xml('xml-content.xml', schemaloc=True)

    # Print the results!
    print results.is_valid

STIX and CybOX Versions
-----------------------

By default, the **stix-validator** will attempt to determine the version of the
input STIX/CybOX document by inspecting the document for version information.

If the input document contains no version information, users must declare
a version for the STIX/CybOX document via the ``version`` parameter:

.. code-block:: python

    import sdv

    # Validate the 'stix-content.xml'.
    # Declare that the STIX content is STIX v1.1.1
    results = sdv.validate_xml('stix-content.xml', version='1.1.1')

    # Print the result!
    print results.is_valid

Unknown Versions
~~~~~~~~~~~~~~~~

If a version is not passed in nor found on the document, one of the following
:class:`.UnknownVersionError` implementations are raised:

* :class:`.UnknownSTIXVersionError` if validating a STIX document.
* :class:`.UnknownCyboxVersionError` if validating a CybOX document.

Invalid Versions
~~~~~~~~~~~~~~~~

If an invalid version is passed in nor found on the document, one of the
following :class:`.InvalidVersionError` implementations are raised:

* :class:`.InvalidSTIXVersionError` if validating a STIX document.
* :class:`.InvalidCyboxVersionError` if validating a CybOX document.


Retrieving XML Schema Validation Errors
---------------------------------------

The following sections explain how to retrieve XML Schema validation errors
from the :class:`.XmlValidationResults` class.

The XmlValidationResults Class
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

XML Schema validation results are communicated via the
:class:`.XmlValidationResults` and :class:`.XmlSchemaError` classes. The
:meth:`sdv.validate_xml` returns an instance of :class:`.XmlValidationResults`.

To determine if a document was valid, users only need to inspect the
``is_valid`` property:

.. code-block:: python

    import sdv

    # Validate the 'xml-content.xml' input document using bundled schemas.
    results = sdv.validate_xml('xml-content.xml')

    # Print the result!
    print results.is_valid

If the ``is_valid`` property is ``False``, users can inspect the ``errors``
property to retrieve specific validation errors.

The ``errors`` property on :class:`.XmlValidationResults` contains a list of
:class:`.XmlSchemaError` instances, which hold details about the validation
errors and methods for accessing those details.

.. code-block:: python

    import sdv

    results = sdv.validate_xml('xml-content.xml')

    # If 'xml-content.xml' is invalid, print each error
    if not results.is_valid:
        for error in results.errors:
            print "Line Number:", error.line
            print "Error Message:", error


Dictionaries and JSON
~~~~~~~~~~~~~~~~~~~~~

Users wanting to work with dictionaries or pass around JSON blobs can make
use of the :meth:`.XmlValidationResults.as_dict()` and
:meth:`.XmlValidationResults.as_json()` methods.

.. code-block:: python

    import sdv

    # Validate 'xml-content.xml'
    results = sdv.validate_xml('xml-content.xml')

    # Retrieve results as dictionary
    result_dictionary = results.as_dict()  # returns {'result': True} if valid

    # Retrieve results as JSON
    result_json = results.as_json() # returns '{"result": true}' JSON if valid

