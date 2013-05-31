#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup
import os
import re


def get_version(package):
    """
    Return package version as listed in `__version__` in `init.py`.
    """
    init_py = open(os.path.join(package, '__init__.py')).read()
    return re.match("__version__ = ['\"]([^'\"]+)['\"]", init_py).group(1)


def get_packages(package):
    """
    Return root package and all sub-packages.
    """
    return [dirpath
            for dirpath, dirnames, filenames in os.walk(package)
            if os.path.exists(os.path.join(dirpath, '__init__.py'))]


def get_package_data(package):
    """
    Return all files under the root package, that are not in a
    package themselves.
    """
    walk = [(dirpath.replace(package + os.sep, '', 1), filenames)
            for dirpath, dirnames, filenames in os.walk(package)
            if not os.path.exists(os.path.join(dirpath, '__init__.py'))]

    filepaths = []
    for base, filenames in walk:
        filepaths.extend([os.path.join(base, filename)
                          for filename in filenames])
    return {package: filepaths}


version = get_version('oauth2_provider')


LONG_DESCRIPTION = open('README.rst').read()

setup(
    name="django-oauth-toolkit",
    version=version,
    description="OAuth2 goodies for the Djangonauts",
    long_description=LONG_DESCRIPTION,
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Environment :: Web Environment",
        "Framework :: Django",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords='django oauth oauth2 oauthlib',
    author="Federico Frenguelli, Massimiliano Pippi",
    author_email='synasius@gmail.com, mpippi@gmail.com',
    url='http://github.com/pydanny/django-admin2',
    license='BSD',
    packages=get_packages('oauth2_provider'),
    package_data=get_package_data('oauth2_provider'),
    test_suite='runtests',
    install_requires=[
        'django>=1.5.0',
        'django-braces==1.0.0',
        'six==1.3.0',
        'oauthlib==0.4.2',
    ],
    zip_safe=False,
)
