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


Update your projects' `urls.py` to include this when you need an OAuth2 provider:

.. code-block:: python

    urlpatterns = patterns(
        ...
        url(r'^o/', include(('oauth2_provider.urls', 'oauth2_provider_app', ), namespace='oauth2_provider'), ),
    )

The example code-block uses the `oauth2_provider` namespace, but feel free to pick another name.
    

Sync your database
------------------

.. sourcecode:: sh

    $ python manage.py migrate oauth2_provider

Next step is our :doc:`first tutorial <tutorial/tutorial_01>`.
