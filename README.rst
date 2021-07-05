Django OAuth Toolkit
====================

.. image:: https://jazzband.co/static/img/badge.svg
   :target: https://jazzband.co/
   :alt: Jazzband

*OAuth2 goodies for the Djangonauts!*

.. image:: https://badge.fury.io/py/django-oauth-toolkit.svg
    :target: http://badge.fury.io/py/django-oauth-toolkit

.. image:: https://github.com/jazzband/django-oauth-toolkit/workflows/Test/badge.svg
   :target: https://github.com/jazzband/django-oauth-toolkit/actions
   :alt: GitHub Actions

.. image:: https://codecov.io/gh/jazzband/django-oauth-toolkit/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/jazzband/django-oauth-toolkit
   :alt: Coverage

.. image:: https://img.shields.io/pypi/pyversions/django-oauth-toolkit.svg
   :target: https://pypi.org/project/django-oauth-toolkit/
   :alt: Supported Python versions

.. image:: https://img.shields.io/pypi/djversions/django-oauth-toolkit.svg
   :target: https://pypi.org/project/django-oauth-toolkit/
   :alt: Supported Django versions

If you are facing one or more of the following:
 * Your Django app exposes a web API you want to protect with OAuth2 authentication,
 * You need to implement an OAuth2 authorization server to provide tokens management for your infrastructure,

Django OAuth Toolkit can help you providing out of the box all the endpoints, data and logic needed to add OAuth2
capabilities to your Django projects. Django OAuth Toolkit makes extensive use of the excellent
`OAuthLib <https://github.com/idan/oauthlib>`_, so that everything is
`rfc-compliant <http://tools.ietf.org/html/rfc6749>`_.

Contributing
------------

We love contributions, so please feel free to fix bugs, improve things, provide documentation. Just `follow the
guidelines <https://django-oauth-toolkit.readthedocs.io/en/latest/contributing.html>`_ and submit a PR.

Reporting security issues
-------------------------

Please report any security issues to the JazzBand security team at <security@jazzband.co>. Do not file an issue on the tracker.

Requirements
------------

* Python 3.6+
* Django 2.2+
* oauthlib 3.1+

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
        path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    ]

Changelog
---------

See `CHANGELOG.md <https://github.com/jazzband/django-oauth-toolkit/blob/master/CHANGELOG.md>`_.


Documentation
--------------

The `full documentation <https://django-oauth-toolkit.readthedocs.io/>`_ is on *Read the Docs*.

License
-------

django-oauth-toolkit is released under the terms of the **BSD license**. Full details in ``LICENSE`` file.
