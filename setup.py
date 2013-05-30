#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup
import os


def get_packages(package):
    """
    Return root package and all sub-packages.
    """
    return [dirpath
            for dirpath, dirnames, filenames in os.walk(package)
            if os.path.exists(os.path.join(dirpath, '__init__.py'))]


LONG_DESCRIPTION = open('README.rst').read()

setup(
    name="django-oauth-toolkit",
    version="0.1.0",
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
    include_package_data=True,
    test_suite='runtests',
    install_requires=[
        'django>=1.5.0',
        'django-braces==1.0.0',
        'oauthlib==0.4.2',
    ],
    zip_safe=False,
)
