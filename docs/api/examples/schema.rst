STIX XML Schema Validation
==========================

The **stix-validator** library provides methods and data types to help perform
XML Schema validation against STIX XML documents. The **stix-validator** library
also bundles all STIX XML Schema files with it and is able to handle most common
XML Schema validation scenarios by only requiring users to provide a
STIX document filename or file-like object.

.. code-block:: python

    import sdv

    # Validate the 'stix-content.xml' STIX document using bundled STIX schemas.
    results = sdv.validate_xml('stix-content.xml')

    # Print the result!
    print results.is_valid

.. note::

    The example above passes the ``stix-content.xml`` filename into
    :meth:`.validate_xml`, but :meth:`.validate_xml` accepts file-like
    objects (such as files on disk or ``StringIO`` instances),
    ``etree._Element`` instances, or ``etree._ElementTree`` instances. Neato!


Using Non-bundled Schemas
-------------------------

Some STIX data may require non-STIX schemas to perform validation. To validate a
STIX document which includes non-STIX, extension data users can provide a path
to a directory containing all the schemas required for validation.

.. code-block:: python

    import sdv

    # Path to a directory containing ALL schema files required for validation
    SCHEMA_DIR = "/path/to/schemas/"

    # Use the `schemas` parameter to use non-bundled schemas.
    results = sdv.validate_xml('stix-content.xml', schemas=SCHEMA_DIR)

Retrieving XML Schema Validation Errors
---------------------------------------

The following sections explain how to retrieve XML Schema validation errors
from the :class:`.XmlValidationResults` class.


The XmlValidationResults Class
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

XML Schema validation results are communicated via the
:class:`.XmlValidationResults` and :class:`.XmlValidationError` classes.

The :meth:`.validate_xml` and :meth:`.XmlSchemaValidator.validate` methods both
return an instance of :class:`.XmlValidationResults`.

To determine if a document was valid, users only need to inspect the
``is_valid`` property:

.. code-block:: python

    import sdv

    # Validate the 'stix-content.xml' STIX document using bundled STIX schemas.
    results = sdv.validate_xml('stix-content.xml')

    # Print the result!
    print results.is_valid

If the ``is_valid`` property is ``False``, users can inspect the ``errors``
property to retrieve specific validation errors:

.. code-block:: python

    import sdv

    results = sdv.validate_xml('stix-content.xml')

    # Read the validation result
    is_valid = results.is_valid

    # If 'stix-content.xml' is invalid, print each error
    if not is_valid:
        for error in results.errors:
            print "Line Number:", error.line
            print "Error Message:", error
