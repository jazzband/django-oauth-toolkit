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


A big *thank you* to the guys from Django REST Framework for inspiring this.


List of available settings
--------------------------

ACCESS_TOKEN_EXPIRE_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~
The number of seconds an access token remains valid. Requesting a protected
resource after this duration will fail. Keep this value high enough so clients
can cache the token for a reasonable amount of time.

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

OAUTH2_SERVER_CLASS
~~~~~~~~~~~~~~~~~~~~
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

SCOPES
~~~~~~
A dictionary mapping each scope name to its human description.

DEFAULT_SCOPES
~~~~~~~~~~~~~~
A list of scopes that should be returned by default.
This is a subset of the keys of the SCOPES setting.
By default this is set to '__all__' meaning that the whole set of SCOPES will be returned.

.. code-block:: python

  DEFAULT_SCOPES = ['read', 'write']

READ_SCOPE
~~~~~~~~~~
The name of the *read* scope.

WRITE_SCOPE
~~~~~~~~~~~
The name of the *write* scope.

REFRESH_TOKEN_EXPIRE_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The number of seconds before a refresh token gets removed from the database by
the ``cleartokens`` management command. Check :ref:`cleartokens` management command for further info.

ROTATE_REFRESH_TOKEN
~~~~~~~~~~~~~~~~~~~~
When is set to `True` (default) a new refresh token is issued to the client when the client refreshes an access token.

REQUEST_APPROVAL_PROMPT
~~~~~~~~~~~~~~~~~~~~~~~
Can be ``'force'`` or ``'auto'``.
The strategy used to display the authorization form. Refer to :ref:`skip-auth-form`.
