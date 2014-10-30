Example Code
============

The following sections demonstrate how to use the **stix-validator** library to
update STIX content. For more details about the **stix-validator** API, see the
:doc:`/api/index` page.

Import stix-validator
---------------------

To use **stix-validator** for validating STIX content, you must import the
``sdv`` module There are lots of functions, classes, and submodules
under ``sdv``, but the top-level module is all you need for most validation
scenarios!

.. code-block:: python

    import sdv  # That's it!

Validating STIX Content
-----------------------

Once you've taken care of the imports, you can call one of the validation 
methods provided by the **stix-validator** library.




STIX Profile Validation
~~~~~~~~~~~~~~~~~~~~~~~

The **stix-validator** provides capabilities for validating STIX instance
documents against `STIX Profiles`_.

.. code-block:: python

    import sdv

    # Path to Excel STIX Profile document
    STIX_PROFILE = "/path/to/stix/profile.xslx

    # Validate the input document against the STIX Profile
    results = sdv.validate_profile('stix-content.xml', STIX_PROFILE)


.. note::

    The :meth:`sdv.validate_profile` method **only** performs STIX Profile
    validation and should be used together with :meth:`sdv.validate_xml` to
    ensure conformance with both the STIX language and STIX Profile.

Retrieving Profile Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The :meth:`sdv.validate_profile` method returns an instance of
:class:`sdv.validators.STIXProfileValidationResults` which has a boolean
``is_valid`` property and ``errors`` property containing a ``list`` of
validation error strings.

.. code-block:: python

    import sdv

    # Path to Excel STIX Profile document
    STIX_PROFILE = "/path/to/stix/profile.xslx

    # Validate the stix-content.xml document against
    results = sdv.validate_profile('stix-content.xml')

    # If 'stix-content.xml' is invalid, print each error
    if not results.is_valid:
        for error in results.errors:
            print "Line Number:", error.line
            print "Error Message:", error



STIX Best Practice Validation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The **stix-validator** can perform validation of `STIX Suggested Practices`_
and report warnings regarding violations:

.. code-block:: python

    import sdv

    results = sdv.validate_best_practices('stix-content.xml')






.. _STIX Profiles: http://stixproject.github.io/documentation/profiles/