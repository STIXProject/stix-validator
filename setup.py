#!/usr/bin/env python

# Copyright (C) 2015 - The MITRE Corporation
# For license information, see the LICENSE.txt file

import sys
from os.path import abspath, dirname, join, realpath
from setuptools import setup, find_packages

BASE_DIR = dirname(abspath(__file__))
VERSION_FILE = join(BASE_DIR, 'sdv', 'version.py')

def get_version():
    with open(VERSION_FILE) as f:
        for line in f.readlines():
            if line.startswith("__version__"):
                version = line.split()[-1].strip('"')
                return version
        raise AttributeError("Package does not have a __version__")


py_maj, py_minor = sys.version_info[:2]

if py_maj != 2:
    raise Exception('stix-validator required Python 2.6/2.7')

if (py_maj, py_minor) < (2, 6):
    raise Exception('stix-validator requires Python 2.6/2.7')

fn_readme = join(BASE_DIR, "README.rst")
with open(fn_readme) as f:
    readme = f.read()

install_requires = ['lxml>=3.3.5', 'xlrd>=0.9.2', 'ordereddict']

extras_require = {
    'docs': [
        'Sphinx==1.2.1',
        'sphinxcontrib-napoleon==0.2.4',
    ],
    'test': [
        "nose==1.3.0",
        "tox==1.6.1"
    ],
}

setup(
    name='stix-validator',
    description='APIs and scripts for validating STIX and CybOX documents.',
    author='The MITRE Corporation',
    author_email='stix@mitre.org',
    url='http://stix.mitre.org/',
    version=get_version(),
    packages=find_packages(),
    scripts=['sdv/scripts/stix_validator.py', 'sdv/scripts/cybox_validator.py'],
    include_package_data=True,
    install_requires=install_requires,
    extras_require=extras_require,
    long_description=readme,
    keywords="stix cybox xml validation validator stix-validator"
)
