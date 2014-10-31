STIX "Best Practices" Validation
================================

The **stix-validator** library provides methods and data types to help perform
`STIX Best Practices`_ validation.

.. _STIX Best Practices: http://stixproject.github.io/documentation/suggested-practices/

.. warning::

    The STIX Best Practices validation capabilities are under active development
    and do not cover all `STIX Best Practices`_.


The following code examples demonstrate different ways you can utilize the
STIX Best Practices validation capabilities in **stix-validator**.

Validating STIX Documents
-------------------------

The **stix-validator** :meth:`sdv.validate_best_practices` method can be used to
validate STIX XML files or file-like objects against `STIX Best Practices`_.

.. code-block:: python

    import sdv

    # Check the 'stix-content.xml' document for STIX Best Practices conformance
    results = sdv.validate_best_practices('stix-content.xml')

    # Print the result!
    print results.is_valid

The :meth:`sdv.validate_best_practices` method acts as a proxy to the
:class:`.STIXBestPracticeValidator` class and is equivalent to the following:

.. code-block:: python

    from sdv.validators import STIXBestPracticeValidator

    # Create the validator instance
    validator = STIXBestPracticeValidator()

    # Validate 'stix-content.xml` STIX document
    results = validator.validate('stix-content.xml')

    # Print the results!
    print results.is_valid


The examples above pass the ``'stix-content.xml'`` filename into
:meth:`sdv.validate_profile` and :meth:`.STIXProfileValidator.validate`, but
these methods can also accept file-like objects (such as files on disk or
``StringIO`` instances), ``etree._Element`` instances, or ``etree._ElementTree``
instances. Neato!


Retrieving STIX Best Practice Validation Errors
-----------------------------------------------

The following sections explain how to retrieve STIX Best Practices validation
errors from the :class:`.BestPracticeValidationResults` class.

The BestPracticeValidationResults Class
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

STIX Best Practices validation results are communicated via the
:class:`.BestPracticeValidationResults`, :class:`BestPracticeWarningCollection`,
and :class:`.BestPracticeWarning` classes.

The :meth:`sdv.validate_best_practices` and
:meth:`.STIXBestPracticeValidator.validate` methods both return an instance of
:class:`.BestPracticeValidationResults`.

To determine if a document was valid, users only need to inspect the
``is_valid`` property:

.. code-block:: python

    import sdv

    # Check the 'stix-content.xml' document for STIX Best Practices conformance
    results = sdv.validate_best_practices('stix-content.xml')

    # Print the result!
    print results.is_valid

If the ``is_valid`` property is ``False``, users can inspect the ``errors``
property to retrieve specific validation errors, or iterate over the
:class:`BestPracticeValidationResults` class directly.

The ``errors`` property on :class:`.BestPracticeValidationResults` contains a
list of :class:`.BestPracticeWarningCollection` instances, which hold details
about the validation errors and methods for accessing those details.

BestPracticeWarnings and Collections
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every violation of STIX Best Practices within an instance document is
represented as an instance of :class:`.BestPracticeWarning`. These violations
are categorized under :class:`.BestPracticeWarningCollection` instances, which
are each assigned names, such as ``"Missing Titles"``, or ``"Duplicate IDs"``.

The ``errors`` property on :class:`.BestPracticeValidationResults` contains a
list of :class:`.BestPracticeWarningCollection` instances, which hold details
about the validation errors and methods for accessing those details.

.. code-block:: python

    import sdv

    # Check the 'stix-content.xml' document for STIX Best Practices conformance
    results = sdv.validate_best_practices('stix-content.xml')

    # If 'stix-content.xml' is invalid, print each error
    if not results.is_valid:
        for coll in results.errors:
            print_best_practice_collection(coll)


The example above iterates over the ``result.errors`` property, and calls
a yet-to-be-defined function, ``print_best_practice_collection()``.

This function `could` be defined as the following:

.. code-block:: python

    def print_best_practice_collection(coll):

        # Print the Best Practice Warning collection name
        print coll.name

        # Print the line and XML tag for each non-conformant node in the
        # warning collection.
        for warning in coll:
            print warning.line, warning.tag

Dictionaries and JSON
~~~~~~~~~~~~~~~~~~~~~

Users wanting to work with dictionaries or pass around JSON blobs can make
use of the :meth:`.BestPracticeValidationResults.as_dict()` and
:meth:`.BestPracticeValidationResults.as_json()` methods.

.. code-block:: python

    import sdv

    # Check the 'stix-content.xml' document for STIX Best Practices conformance
    results = sdv.validate_best_practices('stix-content.xml')

    # Retrieve results as dictionary
    result_dictionary = results.as_dict()  # returns {'result': True} if valid

    # Retrieve results as JSON
    result_json = results.as_json() # returns '{"result": true}' JSON if valid

