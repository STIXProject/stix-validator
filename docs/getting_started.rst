Getting Started
===============

This page gives an introduction to **stix-validator** and how to use it.  Please
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

These instructions tell you how to validate STIX content using the
scripts bundled with **stix-validator**.


STIX Document Validator
~~~~~~~~~~~~~~~~~~~~~~~

Currently, the only script bundled with **stix-validator** is the
``stix_validator.py`` script, which can be found on your ``PATH`` after
installing **stix-validator**.

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

    STIX Document Validator v2.0.0

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

    [-] Initializing STIX XML Schema validator
    [-] Performing xml schema validation on stix-content.xml
    [-] Performing xml schema validation on another-stix-doc.xml
    ============================================================
    [-] Results: stix-content.xml
    [+] XML Schema: True
    ============================================================
    [-] Results: another-stix-doc.xml
    [+] XML Schema: True

