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


fn_readme = join(BASE_DIR, "README.rst")
with open(fn_readme) as f:
    readme = f.read()

install_requires = [
    'xlrd>=0.9.2',
    'ordereddict',
    'python-dateutil',
    'packaging',
    'lxml>=3.3.5',
    'setuptools',
]


extras_require = {
    'docs': [
        'Sphinx==1.3.1',
        'sphinx_rtd_theme==0.1.8',
    ],
    'test': [
        "bumpversion",
        "pytest",
        "tox"
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
    entry_points={
        'console_scripts': [
            'stix-validator = sdv.scripts.stix_validator:main',
            'cybox-validator = sdv.scripts.cybox_validator:main',
            'profile-to-sch = sdv.scripts.profile_to_sch:main',
            'profile-to-xslt = sdv.scripts.profile_to_xslt:main',
        ],
    },
    include_package_data=True,
    install_requires=install_requires,
    extras_require=extras_require,
    long_description=readme,
    keywords='stix cybox xml validation validator stix-validator',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ]
)
