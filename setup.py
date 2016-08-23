#!/usr/bin/env python

# Copyright (c) 2015 - The MITRE Corporation
# For license information, see the LICENSE.txt file

from os.path import abspath, dirname, join
import sys

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

if (py_maj, py_minor) < (2, 6) or (py_maj == 3 and py_minor < 3):
    raise Exception('stix-validator requires Python 2.6, 2.7 or 3.3+')

fn_readme = join(BASE_DIR, "README.rst")
with open(fn_readme) as f:
    readme = f.read()

install_requires = [
    'lxml>=3.3.5',
    'xlrd>=0.9.2',
    'ordereddict',
    'mixbox>=0.0.11',
    'python-dateutil'
]

# Python 2.6 does not come with argparse
try:
    import argparse
except ImportError:
    install_requires.append('argparse')

extras_require = {
    'docs': [
        'Sphinx==1.3.1',
        'sphinx_rtd_theme==0.1.8',
    ],
    'test': [
        "nose==1.3.7",
        "tox==2.3.1"
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
    scripts=['sdv/scripts/stix-validator.py', 'sdv/scripts/cybox-validator.py',
             'sdv/scripts/profile-to-sch.py', 'sdv/scripts/profile-to-xslt.py'],
    include_package_data=True,
    install_requires=install_requires,
    extras_require=extras_require,
    long_description=readme,
    keywords="stix cybox xml validation validator stix-validator"
)
