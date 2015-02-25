Getting Started
===============

This page gives an introduction to **stix-validator** scripts. Please
note that this page is being actively worked on and feedback is welcome! If
you have a suggestion or something doesn't look right, let us know:
(stix@mitre.org).

Note that the GitHub repository is named :code:`stix-validator`, but
once installed, the library is imported using the :code:`import sdv`
statement.

Installation
------------

To install **stix-validator** just run :code:`pip install stix-validator`. If
you have any issues, please refer to the instructions found on the
:doc:`/installation` page.

Scripts
-------

The **stix-validator** library comes with two scripts capable of performing
the validation of STIX and CybOX documents: ``stix_validator.py`` and
``cybox_validator.py``. These scripts can be found on your ``PATH`` after
installing the **stix-validator**.

These instructions tell you how to validate STIX and CybOX content using the
scripts bundled with **stix-validator**.


STIX Document Validator
~~~~~~~~~~~~~~~~~~~~~~~

The ``stix_validator.py`` script can be used to validate STIX content in
a number of ways. The following sections describe the validation options
and expected behavior of the ``stix_validator.py`` script.

Options
^^^^^^^

Running :code:`stix_validator.py -h` displays the following:

.. code-block:: bash

    $ stix_validator.py -h
    usage: stix_validator.py [-h] [--stix-version STIX_VERSION]
                             [--schema-dir SCHEMA_DIR] [--use-schemaloc]
                             [--best-practices] [--profile PROFILE]
                             [--schematron-out SCHEMATRON] [--xslt-out XSLT]
                             [--quiet] [--json-results]
                             [FILES [FILES ...]]

    STIX Document Validator v2.1

    positional arguments:
      FILES                 A whitespace separated list of STIX files or
                            directories of STIX files to validate.

    optional arguments:
      -h, --help            show this help message and exit
      --stix-version STIX_VERSION
                            The version of STIX to validate against
      --schema-dir SCHEMA_DIR
                            Schema directory. If not provided, the STIX schemas
                            bundled with the stix-validator library will be used.
      --use-schemaloc       Use schemaLocation attribute to determine schema
                            locations.
      --best-practices      Check that the document follows authoring best
                            practices
      --profile PROFILE     Path to STIX profile in excel
      --schematron-out SCHEMATRON
                            Path to converted STIX profile schematron file output.
      --xslt-out XSLT       Path to converted STIX profile schematron xslt output.
      --quiet               Only print results and errors if they occur.
      --json-results        Print results as raw JSON. This also sets --quiet.

Example STIX Schema Validation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To perform xml schema validation, just pass in a path to the STIX filename,
filenames, and/or directories containing STIX content.

.. code-block:: bash

    $ stix_validator.py stix-content.xml another-stix-doc.xml

If these documents were valid, the ``stix_validator.py`` script would print
something like the following:

.. code-block:: bash

    [-] Performing xml schema validation on stix-content.xml
    [-] Performing xml schema validation on another-stix-doc.xml
    ============================================================
    [-] Results: stix-content.xml
    [+] XML Schema: True
    ============================================================
    [-] Results: another-stix-doc.xml
    [+] XML Schema: True


CybOX Document Validator
~~~~~~~~~~~~~~~~~~~~~~~~

The ``cybox_validator.py`` script can be used to perform XML Schema validation
on one or more input CybOX documents. The following sections describe the
validation options and expected behavior of the ``cybox_validator.py`` script.

Options
^^^^^^^

The ``cybox_validator.py`` script provides CybOX XML Schema validation
capabilities to your command line.

.. code-block:: bash

    $ cybox_validator.py -h
    usage: cybox_validator.py [-h] [--cybox-version LANG_VERSION]
                              [--schema-dir SCHEMA_DIR] [--use-schemaloc]
                              [--quiet] [--json-results] [--recursive]
                              [FILES [FILES ...]]

    CybOX Document Validator v2.1

    positional arguments:
      FILES                 A whitespace separated list of CybOX files or
                            directories of CybOX files to validate.

    optional arguments:
      -h, --help            show this help message and exit
      --cybox-version LANG_VERSION
                            The version of CybOX to validate against
      --schema-dir SCHEMA_DIR
                            Schema directory. If not provided, the CybOX schemas
                            bundled with the stix-validator library will be used.
      --use-schemaloc       Use schemaLocation attribute to determine schema
                            locations.
      --quiet               Only print results and errors if they occur.
      --json-results        Print results as raw JSON. This also sets --quiet.
      --recursive           Recursively descend into input directories.

Example CybOX Schema Validation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To perform xml schema validation, just pass in a path to the CybOX filename,
filenames, and/or directories containing CybOX content.

.. code-block:: bash

    $ cybox_validator.py cybox-content.xml another-cybox-doc.xml

If these documents were valid, the ``cybox_validator.py`` script would print
something like the following:

.. code-block:: bash

    [-] Performing xml schema validation on cybox-content.xml
    [-] Performing xml schema validation on another-cybox-doc.xml
    ============================================================
    [-] Results: cybox-content.xml
    [+] XML Schema: True
    ============================================================
    [-] Results: another-cybox-doc.xml
    [+] XML Schema: True


Exit Codes
~~~~~~~~~~

Exit status codes for the **stix-validator** bundled scripts are
defined within :mod:`sdv.codes` module.

When invoking the ``stix_validator.py`` or ``cybox_validator.py`` scripts from
another process, developers can inspect the exit code after execution to
determine the results of the validation attempt. Exit status codes can be
combined via bitmasks to convey multiple results (multiple files validated
and/or multiple validation methods selected).

The following script demonstrates an example of invoking ``stix-validator.py``
from another Python script.

.. code-block:: python

    #!/usr/bin/env python

    import subprocess
    import sdv.codes as codes # STIX Document Validator exit codes

    ARGS = [
        'stix_validator.py',
        '--best-practices',
        '--profile',
        'stix-profile.xlsx',
        'stix-document.xml'
    ]

    # Run the stix_validator.py script as a subprocess. Redirect stdout.
    results = subprocess.call(ARGS, stdout=subprocess.PIPE)

    # Check exit status code(s)

    if codes.EXIT_SUCCESS & results:
        print "Input document(s) were valid."

    if codes.EXIT_SCHEMA_INVALID & results:
        print "One or more input files were schema-invalid."

    if codes.EXIT_BEST_PRACTICE_INVALID & results:
        print "One or more input files were STIX Best Practices invalid."

    if codes.EXIT_PROFILE_INVALID & results:
        print "One or more input files were STIX Profile invalid."

    if codes.EXIT_VALIDATION_ERROR & results:
        print "A validation error occurred."

    if codes.EXIT_FAILURE & results:
        print "An unknown, fatal error occurred."

.. note::

    Invoking ``stix_validator.py`` or ``cybox_validator.py`` as a subprocess
    may not always be the best method for validating STIX documents from a
    Python script. The :mod:`sdv` module contains methods for performing STIX
    and CybOX validation!