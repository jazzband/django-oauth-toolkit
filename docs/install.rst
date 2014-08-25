Installation
============

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
        url(r'^o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    )

Sync your database
------------------

.. sourcecode:: sh

    $ python manage.py syncdb
    $ python manage.py migrate oauth2_provider

Next step is our :doc:`first tutorial <tutorial/tutorial_01>`.
