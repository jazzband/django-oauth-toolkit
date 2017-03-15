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
guidelines <https://django-oauth-toolkit.readthedocs.io/en/latest/contributing.html>`_ and submit a PR.

Reporting security issues
-------------------------

If you believe you've found an issue with security implications, please send a detailed description via email to **security@evonove.it**.
Mail sent to that address reaches the Django OAuth Toolkit core team, who can solve (or forward) the security issue as soon as possible. After
our acknowledge, we may decide to open a public discussion in our mailing list or issues tracker.

Once you’ve submitted an issue via email, you should receive a response from the core team within 48 hours, and depending on the action to be
taken, you may receive further followup emails.

Requirements
------------

* Python 2.7, 3.4, 3.5, 3.6
* Django 1.8, 1.10, 1.11
* On Django 1.8: django-braces >= 1.11.0

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

    urlpatterns = [
        ...
        url(r'^o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    ]

Changelog
---------

See `CHANGELOG.md <https://github.com/evonove/django-oauth-toolkit/blob/master/CHANGELOG.md>`_.


Documentation
--------------

The `full documentation <https://django-oauth-toolkit.readthedocs.io/>`_ is on *Read the Docs*.

License
-------

django-oauth-toolkit is released under the terms of the **BSD license**. Full details in ``LICENSE`` file.
