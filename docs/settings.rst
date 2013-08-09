Settings
========

Our configurations are all namespaced under the `OAUTH2_PROVIDER` settings (yes, like Django REST Framework ;) thanks guys!).

For example:

.. code-block:: python

    OAUTH2_PROVIDER = {
        'SCOPES': {
            'read': 'Read scope',
            'write': 'Write scope',
        },

        'CLIENT_ID_GENERATOR_CLASS': 'oauth2_provider.generators.ClientIdGenerator',

    }


Reference
=========

TODO: add reference documentation for DOT settings
