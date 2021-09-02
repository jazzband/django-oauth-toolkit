Settings
========

Our configurations are all namespaced under the `OAUTH2_PROVIDER` settings with the exception of
`OAUTH2_PROVIDER_APPLICATION_MODEL, OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL, OAUTH2_PROVIDER_GRANT_MODEL,
OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL`: this is because of the way Django currently implements
swappable models. See issue #90 (https://github.com/jazzband/django-oauth-toolkit/issues/90) for details.

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
can cache the token for a reasonable amount of time. (default: 36000)

ACCESS_TOKEN_MODEL
~~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your access tokens. Overwrite
this value if you wrote your own implementation (subclass of
``oauth2_provider.models.AccessToken``).

ACCESS_TOKEN_GENERATOR
~~~~~~~~~~~~~~~~~~~~~~
Import path of a callable used to generate access tokens.
oauthlib.oauth2.tokens.random_token_generator is (normally) used if not provided.

ALLOWED_REDIRECT_URI_SCHEMES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Default: ``["http", "https"]``

A list of schemes that the ``redirect_uri`` field will be validated against.
Setting this to ``["https"]`` only in production is strongly recommended.

For Native Apps the ``http`` scheme can be safely used with loopback addresses in the
Application (``[::1]`` or ``127.0.0.1``). In this case the ``redirect_uri`` can be
configured without explicit port specification, so that the Application accepts randomly
assigned ports.

Note that you may override ``Application.get_allowed_schemes()`` to set this on
a per-application basis.


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

EXTRA_SERVER_KWARGS
~~~~~~~~~~~~~~~~~~~
A dictionary to be passed to oauthlib's Server class. Three options
are natively supported: token_expires_in, token_generator,
refresh_token_generator. There's no extra processing so callables (every one
of those three can be a callable) must be passed here directly and classes
must be instantiated (callables should accept request as their only argument).

GRANT_MODEL
~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your grants. Overwrite
this value if you wrote your own implementation (subclass of
``oauth2_provider.models.Grant``).

APPLICATION_ADMIN_CLASS
~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your application admin class.
Overwrite this value if you wrote your own implementation (subclass of
``oauth2_provider.admin.ApplicationAdmin``).

ACCESS_TOKEN_ADMIN_CLASS
~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your access token admin class.
Overwrite this value if you wrote your own implementation (subclass of
``oauth2_provider.admin.AccessTokenAdmin``).

GRANT_ADMIN_CLASS
~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your grant admin class.
Overwrite this value if you wrote your own implementation (subclass of
``oauth2_provider.admin.GrantAdmin``).

REFRESH_TOKEN_ADMIN_CLASS
~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your refresh token admin class.
Overwrite this value if you wrote your own implementation (subclass of
``oauth2_provider.admin.RefreshTokenAdmin``).

OAUTH2_SERVER_CLASS
~~~~~~~~~~~~~~~~~~~
The import string for the ``server_class`` (or ``oauthlib.oauth2.Server`` subclass)
used in the ``OAuthLibMixin`` that implements OAuth2 grant types. It defaults
to ``oauthlib.oauth2.Server``, except when OIDC support is enabled, when the
default is ``oauthlib.openid.Server``.

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
Can be an ``Int`` or ``datetime.timedelta``.

NOTE: This value is completely ignored when validating refresh tokens.
If you don't change the validator code and don't run cleartokens all refresh
tokens will last until revoked or the end of time. You should change this.

REFRESH_TOKEN_GRACE_PERIOD_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The number of seconds between when a refresh token is first used when it is
expired. The most common case of this for this is native mobile applications
that run into issues of network connectivity during the refresh cycle and are
unable to complete the full request/response life cycle. Without a grace
period the application, the app then has only a consumed refresh token and the
only recourse is to have the user re-authenticate. A suggested value, if this
is enabled, is 2 minutes.

REFRESH_TOKEN_MODEL
~~~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your refresh tokens. Overwrite
this value if you wrote your own implementation (subclass of
``oauth2_provider.models.RefreshToken``).

ROTATE_REFRESH_TOKEN
~~~~~~~~~~~~~~~~~~~~
When is set to `True` (default) a new refresh token is issued to the client when the client refreshes an access token.
Known bugs: `False` currently has a side effect of immediately revoking both access and refresh token on refreshing.
See also: validator's rotate_refresh_token method can be overridden to make this variable
(could be usable with expiring refresh tokens, in particular, so that they are rotated
when close to expiration, theoretically).

REFRESH_TOKEN_GENERATOR
~~~~~~~~~~~~~~~~~~~~~~~~~~
See `ACCESS_TOKEN_GENERATOR`. This is the same but for refresh tokens.
Defaults to access token generator if not provided.

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

ERROR_RESPONSE_WITH_SCOPES
~~~~~~~~~~~~~~~~~~~~~~~~~~
When authorization fails due to insufficient scopes include the required scopes in the response.
Only applicable when used with `Django REST Framework <http://django-rest-framework.org/>`_

RESOURCE_SERVER_INTROSPECTION_URL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The introspection endpoint for validating token remotely (RFC7662). This URL requires either an authorization
token (RESOURCE_SERVER_AUTH_TOKEN)
or HTTP Basic Auth client credentials (RESOURCE_SERVER_INTROSPECTION_CREDENTIALS):

RESOURCE_SERVER_AUTH_TOKEN
~~~~~~~~~~~~~~~~~~~~~~~~~~
The bearer token to authenticate the introspection request towards the introspection endpoint (RFC7662).

RESOURCE_SERVER_INTROSPECTION_CREDENTIALS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The HTTP Basic Auth Client_ID and Client_Secret to authenticate the introspection request
towards the introspect endpoint (RFC7662) as a tuple: (client_id,client_secret).

RESOURCE_SERVER_TOKEN_CACHING_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The number of seconds an authorization token received from the introspection endpoint remains valid.
If the expire time of the received token is less than ``RESOURCE_SERVER_TOKEN_CACHING_SECONDS`` the expire time
will be used.


PKCE_REQUIRED
~~~~~~~~~~~~~
Default: ``False``

Whether or not PKCE is required. Can be either a bool or a callable that takes a client id and returns a bool.


OIDC_RSA_PRIVATE_KEY
~~~~~~~~~~~~~~~~~~~~
Default: ``""``

The RSA private key used to sign OIDC ID tokens. If not set, OIDC is disabled.


OIDC_USERINFO_ENDPOINT
~~~~~~~~~~~~~~~~~~~~~~
Default: ``""``

The url of the userinfo endpoint. Used to advertise the location of the
endpoint in the OIDC discovery metadata. Changing this does not change the URL
that ``django-oauth-toolkit`` adds for the userinfo endpoint, so if you change
this you must also provide the service at that endpoint.

If unset, the default location is used, eg if ``django-oauth-toolkit`` is
mounted at ``/o/``, it will be ``<server-address>/o/userinfo/``.

OIDC_ISS_ENDPOINT
~~~~~~~~~~~~~~~~~
Default: ``""``

The URL of the issuer that is used in the ID token JWT and advertised in the
OIDC discovery metadata. Clients use this location to retrieve the OIDC
discovery metadata from ``OIDC_ISS_ENDPOINT`` +
``/.well-known/openid-configuration/``.

If unset, the default location is used, eg if ``django-oauth-toolkit`` is
mounted at ``/o``, it will be ``<server-address>/o``.

OIDC_RESPONSE_TYPES_SUPPORTED
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default::

    [
        "code",
        "token",
        "id_token",
        "id_token token",
        "code token",
        "code id_token",
        "code id_token token",
    ]


The response types that are advertised to be supported by this server.

OIDC_SUBJECT_TYPES_SUPPORTED
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``["public"]``

The subject types that are advertised to be supported by this server.

OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``["client_secret_post", "client_secret_basic"]``

The authentication methods that are advertised to be supported by this server.


Settings imported from Django project
--------------------------

USE_TZ
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Used to determine whether or not to make token expire dates timezone aware.
