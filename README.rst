Django OAuth Toolkit
====================

*OAuth2 goodies for the Djangonauts!*

.. image:: https://badge.fury.io/py/django-oauth-toolkit.png
    :target: http://badge.fury.io/py/django-oauth-toolkit

.. image:: https://travis-ci.org/evonove/django-oauth-toolkit.png
   :alt: Build Status
   :target: https://travis-ci.org/evonove/django-oauth-toolkit

.. image:: https://coveralls.io/repos/evonove/django-oauth-toolkit/badge.png
   :alt: Coverage Status
   :target: https://coveralls.io/r/evonove/django-oauth-toolkit

If you are facing one or more of the following:
 * Your Django app exposes a web API you want to protect with OAuth2 authentication,
 * You need to implement an OAuth2 authorization server to provide tokens management for your infrastructure,

Django OAuth Toolkit can help you providing out of the box all the endpoints, data and logic needed to add OAuth2
capabilities to your Django projects. Django OAuth Toolkit makes extensive use of the excellent
`OAuthLib <https://github.com/idan/oauthlib>`_, so that everything is
`rfc-compliant <http://tools.ietf.org/html/rfc6749>`_.

Support
-------

If you need support please send a message to the `Django OAuth Toolkit Google Group <http://groups.google.com/group/django-oauth-toolkit>`_

Contributing
------------

We love contributions, so please feel free to fix bugs, improve things, provide documentation. Just `follow the
guidelines <https://django-oauth-toolkit.readthedocs.org/en/latest/contributing.html>`_ and submit a PR.

Requirements
------------

* Python 2.6, 2.7, 3.3, 3.4
* Django 1.4, 1.5, 1.6, 1.7, 1.8

Installation
------------

Install with pip::

    pip install django-oauth-toolkit

Add `oauth2_provider` to your `INSTALLED_APPS`

.. code-block:: python

    INSTALLED_APPS = (
        ...
        'oauth2_provider',
    )


If you need an OAuth2 provider you'll want to add the following to your urls.py.
Notice that `oauth2_provider` namespace is mandatory.

.. code-block:: python

    urlpatterns = patterns(
        ...
        url(r'^o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    )

Documentation
--------------

The `full documentation <https://django-oauth-toolkit.readthedocs.org/>`_ is on *Read the Docs*.

License
-------

django-oauth-toolkit is released under the terms of the **BSD license**. Full details in ``LICENSE`` file.

Roadmap / Todo list (help wanted)
---------------------------------

* OAuth1 support
* OpenID connector
* Nonrel storages support

Changelog
---------

master
~~~~~~~~~~~~~~~~~~

* #273: Generic read write scope by resource

0.9.0 [2015-07-28]
~~~~~~~~~~~~~~~~~~

* ``oauthlib_backend_class`` is now pluggable through Django settings
* #127: ``application/json`` Content-Type is now supported using ``JSONOAuthLibCore``
* #238: Fixed redirect uri handling in case of error
* #229: Invalidate access tokens when getting a new refresh token
* added support for oauthlib 1.0

0.8.2 [2015-06-25]
~~~~~~~~~~~~~~~~~~

* Fix the migrations to be two-step and allow upgrade from 0.7.2

0.8.1 [2015-04-27]
~~~~~~~~~~~~~~~~~~

* South migrations fixed. Added new django migrations.

0.8.0 [2015-03-27]
~~~~~~~~~~~~~~~~~~

* Several docs improvements and minor fixes
* #185: fixed vulnerabilities on Basic authentication
* #173: ProtectResourceMixin now allows OPTIONS requests
* Fixed client_id and client_secret characters set
* #169: hide sensitive informations in error emails
* #161: extend search to all token types when revoking a token
* #160: return empty response on successful token revocation
* #157: skip authorization form with ``skip_authorization_completely`` class field
* #155: allow custom uri schemes
* fixed ``get_application_model`` on Django 1.7
* fixed non rotating refresh tokens
* #137: fixed base template
* customized ``client_secret`` lenght
* #38: create access tokens not bound to a user instance for *client credentials* flow

0.7.2 [2014-07-02]
~~~~~~~~~~~~~~~~~~

* Don't pin oauthlib

0.7.1 [2014-04-27]
~~~~~~~~~~~~~~~~~~

* Added database indexes to the OAuth2 related models to improve performances.

**Warning: schema migration does not work for sqlite3 database, migration should be performed manually**

0.7.0 [2014-03-01]
~~~~~~~~~~~~~~~~~~

* Created a setting for the default value for approval prompt.
* Improved docs
* Don't pin django-braces and six versions

**Backwards incompatible changes in 0.7.0**

* Make Application model truly "swappable" (introduces a new non-namespaced setting OAUTH2_PROVIDER_APPLICATION_MODEL)

0.6.1 [2014-02-05]
~~~~~~~~~~~~~~~~~~

* added support for `scope` query parameter keeping backwards compatibility for the original `scopes` parameter.
* __str__ method in Application model returns content of `name` field when available

0.6.0 [2014-01-26]
~~~~~~~~~~~~~~~~~~

* oauthlib 0.6.1 support
* Django dev branch support
* Python 2.6 support
* Skip authorization form via `approval_prompt` parameter

**Bugfixes**

* Several fixes to the docs
* Issue #71: Fix migrations
* Issue #65: Use OAuth2 password grant with multiple devices
* Issue #84: Add information about login template to tutorial.
* Issue #64: Fix urlencode clientid secret

0.5.0 [2013-09-17]
~~~~~~~~~~~~~~~~~~

* oauthlib 0.6.0 support

**Backwards incompatible changes in 0.5.0**

* `backends.py` module has been renamed to `oauth2_backends.py` so you should change your imports whether
  you're extending this module

**Bugfixes**

* Issue #54: Auth backend proposal to address #50
* Issue #61: Fix contributing page
* Issue #55: Add support for authenticating confidential client with request body params
* Issue #53: Quote characters in the url query that are safe for Django but not for oauthlib

0.4.1 [2013-09-06]
~~~~~~~~~~~~~~~~~~

* Optimize queries on access token validation

0.4.0 [2013-08-09]
~~~~~~~~~~~~~~~~~~

**New Features**

* Add Application management views, you no more need the admin to register, update and delete your application.
* Add support to configurable application model
* Add support for function based views

**Backwards incompatible changes in 0.4.0**

* `SCOPE` attribute in settings is now a dictionary to store `{'scope_name': 'scope_description'}`
* Namespace 'oauth2_provider' is mandatory in urls. See issue #36

**Bugfixes**

* Issue #25: Bug in the Basic Auth parsing in Oauth2RequestValidator
* Issue #24: Avoid generation of client_id with ":" colon char when using HTTP Basic Auth
* Issue #21: IndexError when trying to authorize an application
* Issue #9: Default_redirect_uri is mandatory when grant_type is implicit, authorization_code or all-in-one
* Issue #22: Scopes need a verbose description
* Issue #33: Add django-oauth-toolkit version on example main page
* Issue #36: Add mandatory namespace to urls
* Issue #31: Add docstring to OAuthToolkitError and FatalClientError
* Issue #32: Add docstring to validate_uris
* Issue #34: Documentation tutorial part1 needs corsheaders explanation
* Issue #36: Add mandatory namespace to urls
* Issue #45: Add docs for AbstractApplication
* Issue #47: Add docs for views decorators


0.3.2 [2013-07-10]
~~~~~~~~~~~~~~~~~~

* Bugfix #37: Error in migrations with custom user on Django 1.5

0.3.1 [2013-07-10]
~~~~~~~~~~~~~~~~~~

* Bugfix #27: OAuthlib refresh token refactoring

0.3.0 [2013-06-14]
~~~~~~~~~~~~~~~~~~

* `Django REST Framework <http://django-rest-framework.org/>`_ integration layer
* Bugfix #13: Populate request with client and user in validate_bearer_token
* Bugfix #12: Fix paths in documentation

**Backwards incompatible changes in 0.3.0**

* `requested_scopes` parameter in ScopedResourceMixin changed to `required_scopes`

0.2.1 [2013-06-06]
~~~~~~~~~~~~~~~~~~

* Core optimizations

0.2.0 [2013-06-05]
~~~~~~~~~~~~~~~~~~

* Add support for Django1.4 and Django1.6
* Add support for Python 3.3
* Add a default ReadWriteScoped view
* Add tutorial to docs

0.1.0 [2013-05-31]
~~~~~~~~~~~~~~~~~~

* Support OAuth2 Authorization Flows

0.0.0 [2013-05-17]
~~~~~~~~~~~~~~~~~~

* Discussion with Daniel Greenfeld at Django Circus
* Ignition
