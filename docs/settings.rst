Settings
========

Our configurations are all namespaced under the `OAUTH2_PROVIDER` settings with the exception of
`OAUTH2_PROVIDER_APPLICATION_MODEL, OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL, OAUTH2_PROVIDER_GRANT_MODEL,
OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL`: this is because of the way Django currently implements
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


A big *thank you* to the guys from Django REST Framework for inspiring this.


List of available settings
--------------------------

ACCESS_TOKEN_EXPIRE_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~
The number of seconds an access token remains valid. Requesting a protected
resource after this duration will fail. Keep this value high enough so clients
can cache the token for a reasonable amount of time.

ACCESS_TOKEN_MODEL
~~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your access tokens. Overwrite
this value if you wrote your own implementation (subclass of
``oauth2_provider.models.AccessToken``).

ALLOWED_REDIRECT_URI_SCHEMES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Default: ``["http", "https"]``

A list of schemes that the ``redirect_uri`` field will be validated against.
Setting this to ``["https"]`` only in production is strongly recommended.

APPLICATION_MODEL
~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your applications. Overwrite
this value if you wrote your own implementation (subclass of
``oauth2_provider.models.Application``).

AUTHORIZATION_CODE_EXPIRE_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The number of seconds an authorization code remains valid. Requesting an access
token after this duration will fail. :rfc:`4.1.2` recommends a
10 minutes (600 seconds) duration.

CLIENT_ID_GENERATOR_CLASS
~~~~~~~~~~~~~~~~~~~~~~~~~
The import string of the class responsible for generating client identifiers.
These are usually random strings.

CLIENT_SECRET_GENERATOR_CLASS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The import string of the class responsible for generating client secrets.
These are usually random strings.

CLIENT_SECRET_GENERATOR_LENGTH
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The length of the generated secrets, in characters. If this value is too low,
secrets may become subject to bruteforce guessing.

GRANT_MODEL
~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your grants. Overwrite
this value if you wrote your own implementation (subclass of
``oauth2_provider.models.Grant``).

OAUTH2_SERVER_CLASS
~~~~~~~~~~~~~~~~~~~
The import string for the ``server_class`` (or ``oauthlib.oauth2.Server`` subclass)
used in the ``OAuthLibMixin`` that implements OAuth2 grant types.

OAUTH2_VALIDATOR_CLASS
~~~~~~~~~~~~~~~~~~~~~~
The import string of the ``oauthlib.oauth2.RequestValidator`` subclass that
validates every step of the OAuth2 process.

OAUTH2_BACKEND_CLASS
~~~~~~~~~~~~~~~~~~~~
The import string for the ``oauthlib_backend_class`` used in the ``OAuthLibMixin``,
to get a ``Server`` instance.

REFRESH_TOKEN_EXPIRE_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The number of seconds before a refresh token gets removed from the database by
the ``cleartokens`` management command. Check :ref:`cleartokens` management command for further info.

REFRESH_TOKEN_MODEL
~~~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your refresh tokens. Overwrite
this value if you wrote your own implementation (subclass of
``oauth2_provider.models.RefreshToken``).

ROTATE_REFRESH_TOKEN
~~~~~~~~~~~~~~~~~~~~
When is set to `True` (default) a new refresh token is issued to the client when the client refreshes an access token.

REQUEST_APPROVAL_PROMPT
~~~~~~~~~~~~~~~~~~~~~~~
Can be ``'force'`` or ``'auto'``.
The strategy used to display the authorization form. Refer to :ref:`skip-auth-form`.

SCOPES_BACKEND_CLASS
~~~~~~~~~~~~~~~~~~~~
**New in 0.12.0**. The import string for the scopes backend class.
Defaults to ``oauth2_provider.scopes.SettingsScopes``, which reads scopes through the settings defined below.

SCOPES
~~~~~~
.. note:: (0.12.0+) Only used if `SCOPES_BACKEND_CLASS` is set to the SettingsScopes default.

A dictionary mapping each scope name to its human description.

.. _settings_default_scopes:

DEFAULT_SCOPES
~~~~~~~~~~~~~~
.. note:: (0.12.0+) Only used if `SCOPES_BACKEND_CLASS` is set to the SettingsScopes default.

A list of scopes that should be returned by default.
This is a subset of the keys of the SCOPES setting.
By default this is set to '__all__' meaning that the whole set of SCOPES will be returned.

.. code-block:: python

  DEFAULT_SCOPES = ['read', 'write']

READ_SCOPE
~~~~~~~~~~
.. note:: (0.12.0+) Only used if `SCOPES_BACKEND_CLASS` is set to the SettingsScopes default.

The name of the *read* scope.

WRITE_SCOPE
~~~~~~~~~~~
.. note:: (0.12.0+) Only used if `SCOPES_BACKEND_CLASS` is set to the SettingsScopes default.

The name of the *write* scope.

RESOURCE_SERVER_INTROSPECTION_URL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The introspection endpoint for validating token remotely (RFC7662).

RESOURCE_SERVER_AUTH_TOKEN
~~~~~~~~~~~~~~~~~~~~~~~~~~
The bearer token to authenticate the introspection request towards the introspection endpoint (RFC7662).


RESOURCE_SERVER_TOKEN_CACHING_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The number of seconds an authorization token received from the introspection endpoint remains valid.
If the expire time of the received token is less than ``RESOURCE_SERVER_TOKEN_CACHING_SECONDS`` the expire time
will be used.
