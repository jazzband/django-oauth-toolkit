Settings
========

Our configurations are all namespaced under the `OAUTH2_PROVIDER` settings with the solely exception of
`OAUTH2_PROVIDER_APPLICATION_MODEL`: this is because of the way Django currently implements
swappable models. See issue #90 (https://github.com/evonove/django-oauth-toolkit/issues/90) for details.

For example:

.. code-block:: python

    OAUTH2_PROVIDER = {
        'SCOPES': {
            'read': 'Read scope',
            'write': 'Write scope',
        },

        'CLIENT_ID_GENERATOR_CLASS': 'oauth2_provider.generators.ClientIdGenerator',

    }


TODO: add reference documentation for DOT settings

A big *thank you* to the guys from Django REST Framework for inspiring this.