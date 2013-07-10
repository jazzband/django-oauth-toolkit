Django OAuth Toolkit
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

Documentation
--------------

The `full documentation <https://django-oauth-toolkit.readthedocs.org/en/latest/>`_ is on *Read the Docs*.

License
-------

django-oauth-toolkit is released under the terms of the **BSD license**. Full details in ``LICENSE`` file.

Roadmap
-------------------------------

Highest priority first

 * ``django-rest-framework`` integration
 * Test server deployment
 * OAuth2 client wrapper
 * OAuth1 support

Changelog
---------

0.3.2 [2013-07-10]

 * Bugfix #37: Error in migrations with custom user on Django 1.5

0.3.1 [2013-07-10]

 * Bugfix #27: OAuthlib refresh token refactoring

0.3.0 [2013-06-14]

 * `Django REST Framework <http://django-rest-framework.org/>`_ integration layer
 * Bugfix #13: Populate request with client and user in validate_bearer_token
 * Bugfix #12: Fix paths in documentation

**Backwards incompatible changes in 0.3.0**

 * `requested_scopes` parameter in ScopedResourceMixin changed to `required_scopes`

0.2.1 [2013-06-06]

 * Core optimizations

0.2.0 [2013-06-05]

 * Add support for Django1.4 and Django1.6
 * Add support for Python 3.3
 * Add a default ReadWriteScoped view
 * Add tutorial to docs

0.1.0 [2013-05-31]

 * Support OAuth2 Authorization Flows

0.0.0 [2013-05-17]

 * Discussion with Daniel Greenfeld at Django Circus
 * Ignition
