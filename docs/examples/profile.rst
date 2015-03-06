STIX Profile Validation
=======================

The **stix-validator** library provides methods and data types to help perform
`STIX Profile`_ validation.

.. _STIX Profile: http://stixproject.github.io/documentation/profiles/

.. warning::

    The STIX Profile validation capabilities should be considered
    **experimental** and may change considerably over time.


The following code examples demonstrate different ways you can utilize the
STIX Profile validation capabilities in **stix-validator**.

Validating STIX Documents
-------------------------

The **stix-validator** :meth:`sdv.validate_profile` method can be used to
validate STIX XML files or file-like objects agains a `STIX Profile`_.

.. code-block:: python

    import sdv

    # STIX Profile filename
    PROFILE = "/path/to/stix/profile.xlsx"

    # Validate the 'stix-content.xml' STIX document against the PROFILE doc
    results = sdv.validate_profile('stix-content.xml', PROFILE)

    # Print the result!
    print results.is_valid

The :meth:`sdv.validate_profile` method acts as a proxy to the
:class:`.STIXProfileValidator` class and is equivalent to the following:

.. code-block:: python

    from sdv.validators import STIXProfileValidator

    # STIX Profile filename
    PROFILE = "/path/to/stix/profile.xlsx"

    # Create the validator instance for PROFILE
    validator = STIXProfileValidator(PROFILE)

    # Validate 'stix-content.xml` STIX document against the PROFILE
    results = validator.validate('stix-content.xml')

    # Print the results!
    print results.is_valid


.. note::

    When validating multiple documents against a STIX Profile, using the
    :class:`.STIXProfileValidator` will be faster than
    :meth:`sdv.validate_profile` since :meth:`sdv.validate_profile` needs to
    parse the STIX Profile with each invocation.

The examples above pass the ``'stix-content.xml'`` filename into
:meth:`sdv.validate_profile` and :meth:`.STIXProfileValidator.validate`, but
these methods can also accept file-like objects (such as files on disk or
``StringIO`` instances), ``etree._Element`` instances, or ``etree._ElementTree``
instances. Neato!


Retrieving STIX Profile Validation Errors
-----------------------------------------

The following sections explain how to retrieve STIX Profile validation errors
from the :class:`.ProfileValidationResults` class.

The ProfileValidationResults Class
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

STIX Profile validation results are communicated via the
:class:`.ProfileValidationResults` and :class:`.ProfileError` classes.

The :meth:`sdv.validate_profile` and :meth:`.STIXProfileValidator.validate`
methods both return an instance of :class:`.ProfileValidationResults`.

To determine if a document was valid, users only need to inspect the
``is_valid`` property:

.. code-block:: python

    import sdv

    # STIX Profile filename
    PROFILE = "/path/to/stix/profile.xlsx"

    # Validate the 'stix-content.xml' STIX document against the PROFILE doc
    results = sdv.validate_profile('stix-content.xml', PROFILE)

    # Print the result!
    print results.is_valid

If the ``is_valid`` property is ``False``, users can inspect the ``errors``
property to retrieve specific validation errors.

The ``errors`` property on :class:`.ProfileValidationResults` contains a list of
:class:`.ProfileError` instances, which hold details about the validation
errors and methods for accessing those details.

.. code-block:: python

    import sdv

    # STIX Profile filename
    PROFILE = "/path/to/stix/profile.xlsx"

    # Validate the 'stix-content.xml' STIX document against the PROFILE doc
    results = sdv.validate_profile('stix-content.xml', PROFILE)

    # If 'stix-content.xml' is invalid, print each error
    if not results.is_valid:
        for error in results.errors:
            print "Line Number:", error.line
            print "Error Message:", error


Dictionaries and JSON
~~~~~~~~~~~~~~~~~~~~~

Users wanting to work with dictionaries or pass around JSON blobs can make
use of the :meth:`.ProfileValidationResults.as_dict()` and
:meth:`.ProfileValidationResults.as_json()` methods.

.. code-block:: python

    import sdv

    # STIX Profile filename
    PROFILE = "/path/to/stix/profile.xlsx"

    # Validate the 'stix-content.xml' STIX document against the PROFILE doc
    results = sdv.validate_profile('stix-content.xml', PROFILE)

    # Retrieve results as dictionary
    result_dictionary = results.as_dict()  # returns {'result': True} if valid

    # Retrieve results as JSON
    result_json = results.as_json() # returns '{"result": true}' JSON if valid


Converting STIX Profiles to XSLT and Schematron
-----------------------------------------------

STIX Profiles are currently defined using multi-worksheet Excel documents. The
**stix-validator** API provides methods for converting Excel documents into
`ISO Schematron`_ and `XSLT`_ documents.

.. _ISO Schematron: http://www.schematron.com/
.. _XSLT: http://www.w3.org/TR/xslt

.. code-block:: python

    import sdv

    # STIX Profile filename
    PROFILE = "/path/to/stix/profile.xlsx"

    # Convert the STIX Profile into a Schematron document
    schematron = sdv.profile_to_schematron(PROFILE)

    # Convert the STIX Profile into an XSLT document
    xslt = sdv.profile_to_xslt(PROFILE)

    # Write the returned Scheamtron document to a file
    schematron.write(
        "/path/to/output/filename.sch",  # Output Schematron file path
        pretty_print=True,               # Pretty print the file (not necessary)
        xml_declaration=True,            # Write out <?xml version="1.0" encoding="UTF-8"?>
        encoding="UTF-8"                 # Set the encoding to UTF-8
    )

    # Write out the returned XSLT document to a file
    xslt.write(
        "/path/to/output/filename.xslt", # Output XSLT file path
        pretty_print=True,               # Pretty print the file (not necessary)
        xml_declaration=True,            # Write out <?xml version="1.0" encoding="UTF-8"?>
        encoding="UTF-8"                 # Set the encoding to UTF-8
    )

