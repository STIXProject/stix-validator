STIX Document Validator
=======================

A Python tool and API that validates STIX and CybOX XML instance documents.

.. _STIX XML Schema: https://stixproject.github.io/releases/1.2/
.. _CybOX XML Schema: https://cyboxproject.github.io/releases/2.1/
.. _STIX Profiles: http://stixproject.github.io/documentation/profiles/
.. _STIX Best Practices: http://stixproject.github.io/documentation/suggested-practices/

:Source: https://github.com/STIXProject/stix-validator
:Documentation: http://stix-validator.readthedocs.org
:Information: https://stixproject.github.io | https://cyboxproject.github.io

|travis badge| |health badge| |version badge|

.. |travis badge| image:: https://api.travis-ci.org/STIXProject/stix-validator.svg?branch=master
   :target: https://travis-ci.org/STIXProject/stix-validator
   :alt: Build Status
.. |health badge| image:: https://landscape.io/github/STIXProject/stix-validator/master/landscape.svg?style=flat
   :target: https://landscape.io/github/STIXProject/stix-validator/master
   :alt: Code Health
.. |version badge| image:: https://img.shields.io/pypi/v/stix-validator.svg?maxAge=3600
   :target: https://pypi.python.org/pypi/stix-validator/
   :alt: PyPI Version Badge

Validation
----------

The **STIX Document Validator (sdv)** can perform the following forms of
STIX document validation:

* `STIX XML Schema`_: Validate STIX documents against bundled or external
  STIX schemas.
* `STIX Profiles`_: Verify STIX Profile conformance (**experimental**)
* `STIX Best Practices`_: Verify alignment with STIX Best Practices.

The following forms of CybOX document validation are also possible:

* `CybOX XML Schema`_

Dependencies
------------

The **STIX Document Validator** has the following dependencies:

* `Python`_: Python interpreter
* `lxml`_ >= v3.2.0: XML processing library.

  * `libxml2`_ >= v2.9.1: Required XML processing C 
    library for ``lxml``.
* `xlrd`_ >= v0.9.2: XLSX library for parsing STIX Profiles.

.. _Python: http://python.org/download
.. _lxml: http://lxml.de/index.html#download
.. _libxml2: http://www.xmlsoft.org/downloads.html
.. _xlrd: https://pypi.python.org/pypi/xlrd

For a Windows installer of lxml, we recommend looking here: 
http://www.lfd.uci.edu/~gohlke/pythonlibs/#lxml

The **STIX Document Validator** supports Python 3.8+.


Installation
------------

The recommended method for installing the **STIX Document Validator** is via
``pip``.

::

  $ pip install stix-validator

This will install the ``sdv`` package into your Python installation's
``site-packages`` and four scripts found under ``sdv/scripts`` on your ``PATH``.


How To Use
----------

The **STIX Document Validator** bundles four scripts: ``stix_validator.py``,
``profile_to_sch.py``, ``profile_to_xslt.py``, and ``cybox_validator.py``,

STIX Validation
"""""""""""""""

The ``stix_validator.py`` script  can can validate a STIX XML document against
STIX schemas, STIX Best Practices, and STIX Profiles.

**NOTE:** The STIX Profile validation should be considered **experimental.**

**Validate using bundled schemas**

.. code-block:: bash

  $ stix-validator <stix_document.xml>

**Validate using schemaLocation**  

.. code-block:: bash

  $ stix-validator --use-schemaloc <stix_document.xml>

**Validate using non-bundled schemas**

.. code-block:: bash

  $ stix-validator --schema-dir </path/to/schemas> <stix_document.xml>
  
**NOTE:** If you are trying to validate a STIX document from a checked-out
copy of STIX schema repository, make sure you have also cloned the CybOX 
schema submodule with ``git submodule init`` and ``git submodule update``.

**Validate a directory of STIX documents**  

.. code-block:: bash

  $ stix-validator </path/to/stix_dir>

**Validate multiple files and/or directories**  

.. code-block:: bash

  $ stix-validator <one.xml> <two.xml> <directory_of_files> ...

**Check "best practice" guidance**  

.. code-block:: bash

    $ stix-validator --best-practices <stix_document.xml>

**Validate using STIX Profile**  

.. code-block:: bash

    $ stix-validator --profile <stix_profile.xlsx> <stix_document.xml>


STIX Profile to Schematron Conversion
"""""""""""""""""""""""""""""""""""""

The ``profile_to_sch.py`` script performs a conversion from a valid STIX profile
to schematron.

.. code-block:: bash

  $ profile-to-sch <valid_stix_profile.xlsx>

Schematron output is sent to stdout.

STIX Profile to XSLT Conversion
"""""""""""""""""""""""""""""""

The ``profile_to_xslt.py`` script performs a conversion from a valid STIX profile
to XSLT.

.. code-block:: bash

  $ profile-to-xslt <valid_stix_profile.xlsx>

XSLT output is sent to stdout.

CybOX Validation
""""""""""""""""

The ``cybox_validator.py`` script can perform CybOX XML Schema validation.

**Validate using bundled schemas**

.. code-block:: bash

  $ cybox-validator <cybox_document.xml>

**Validate using schemaLocation**

.. code-block:: bash

  $ cybox-validator --use-schemaloc <cybox_document.xml>

**Validate using non-bundled schemas**

.. code-block:: bash

  $ cybox-validator --schema-dir </path/to/schemas> <cybox_document.xml>

**Validate a directory of CybOX documents**

.. code-block:: bash

  $ cybox-validator </path/to/cybox_dir>

**Validate multiple files and/or directories**

.. code-block:: bash

  $ cybox-validator <one.xml> <two.xml> <directory_of_files> ...


All STIX and CybOX Documents?
-----------------------------

The **STIX Document Validator** bundles XML schemas with it, which
includes all STIX (v1.0 through v1.2.1) and CybOX (2.0 through v2.1) schema
files. If a document includes instances of schematic constructs defined
outside of the STIX or CybOX languages, a user must point the
**STIX Document Validator** scripts at those schemas in order to validate.

To use schemas other than those bundled with the **STIX Document Validator**
use the ``--schemas-dir`` flag to pass in a path to a schema directory.

Common Libxml2 Error
--------------------

Users often report an error which looks something like the following:

::

    Fatal error occurred: local union type: A type, derived by list or union, must have the
    simple ur-type definition as base type, not '{http://cybox.mitre.org/common-2}(NULL)'., line 350

This error is caused by an insufficient version of libxml2 being installed
on the system. The **STIX Document Validator** requires ``libxml2`` v2.9.1 at
a minimum and is not guaranteed to work properly with earlier versions.

To see what version of libxml2 you have installed, execute the
``xml2-config --version`` command and make sure you are running at least v2.9.1.

Terms
-----

BY USING THE STIX DOCUMENT VALIDATOR, YOU SIGNIFY YOUR ACCEPTANCE OF THE 
TERMS AND CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE 
THE STIX DOCUMENT VALIDATOR.

For more information, please refer to the LICENSE.txt file
