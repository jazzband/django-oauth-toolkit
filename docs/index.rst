.. Django OAuth Toolkit documentation master file, created by
   sphinx-quickstart on Mon May 20 19:40:43 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Django OAuth Toolkit Documentation
====================

*OAuth2 goodies for the Djangonauts!*

.. image:: https://travis-ci.org/evonove/django-oauth-toolkit.png
   :alt: Build Status
   :target: https://travis-ci.org/evonove/django-oauth-toolkit
.. image:: https://coveralls.io/repos/evonove/django-oauth-toolkit/badge.png
   :alt: Coverage Status
   :target: https://coveralls.io/r/evonove/django-oauth-toolkit

If you are facing one or more of the following:
 * Your Django app needs to interact with an OAuth2 authorization server to access 3rd party resources,
 * Your Django app exposes a web API you want to protect with OAuth2 authentication,
 * You need to implement an OAuth2 authorization server to provide tokens management for your infrastructure,

Django OAuth Toolkit can help you providing out of the box all the endpoints, data and logic needed to add OAuth2
capabilities to your Django projects. Django OAuth Toolkit makes extensive use of the excellent
`OAuthLib <https://github.com/idan/oauthlib>`_, so that everything is
`rfc-compliant <http://tools.ietf.org/html/rfc6749>`_.

See our :doc:`Changelog <changelog>` for information on updates.

Requirements
------------

* Python 2.7, 3.3
* Django 1.4, 1.5, 1.6a1

Installation
------------

Install with pip

    pip install django-oauth-toolkit

Add `oauth2_provider` to your `INSTALLED_APPS`

.. code-block:: python

    INSTALLED_APPS = (
        ...
        'oauth2_provider',
    )


If you need an OAuth2 provider you'll want to add the following to your urls.py

.. code-block:: python

    urlpatterns = patterns(
        ...
        url(r'^o/', include('oauth2_provider.urls')),
    )

Next step is our :doc:`first tutorial <tutorial_01>`.

Tutorial
========

.. toctree::
   :maxdepth: 1

   tutorial_01
   tutorial_02
   tutorial_03

API
====

.. toctree::
   :maxdepth: 2

   models
   views

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
