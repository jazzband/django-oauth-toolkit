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

0.1.0 [2013-05-31]

 * Support OAuth2 Authorization Flows

0.0.0 [2013-05-17]

 * Discussion with Daniel Greenfeld at Django Circus
 * Ignition
