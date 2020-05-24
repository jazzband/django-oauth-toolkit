Installation
============

Install with pip
::
    pip install django-oauth-toolkit

Add `oauth2_provider` to your `INSTALLED_APPS`

.. code-block:: python

    INSTALLED_APPS = (
        ...
        'oauth2_provider',
    )


If you need an OAuth2 provider you'll want to add the following to your urls.py

.. code-block:: python

    from django.urls import include, path

    urlpatterns = [
        ...
        path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    ]

Or using `re_path()`

.. code-block:: python

    from django.urls import include, re_path

    urlpatterns = [
        ...

        re_path(r'^o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    ]

Sync your database
------------------

.. sourcecode:: sh

    $ python manage.py migrate oauth2_provider

Next step is our :doc:`first tutorial <tutorial/tutorial_01>`.
