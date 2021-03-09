OpenID Connect
++++++++++++++

OpenID Connect support
======================

``django-oauth-toolkit`` supports OpenID Connect (OIDC), which standardizes
authentication flows and provides a plug and play integration with other
systems. OIDC is built on top of OAuth 2.0 to provide:

* Generating ID tokens as part of the login process. These are JWT that
  describe the user, and can be used to authenticate them to your application.
* Metadata based auto-configuration for providers
* A user info endpoint, which applications can query to get more information
  about a user.

Enabling OIDC doesn't affect your existing OAuth 2.0 flows, these will
continue to work alongside OIDC.

We support:

* OpenID Connect Authorization Code Flow
* OpenID Connect Implicit Flow
* OpenID Connect Hybrid Flow


Configuration
=============

OIDC is not enabled by default because it requires additional configuration
that must be provided. ``django-oauth-toolkit`` supports two different
algorithms for signing JWT tokens, ``RS256``, which uses asymmetric RSA keys (a
public key and a private key), and ``HS256``, which uses a symmetric key.

It is preferrable to use ``RS256``, because this produces a token that can be
verified by anyone using the public key (which is made available and
discoverable by OIDC service auto-discovery, included with
``django-oauth-toolkit``). ``HS256`` on the other hand uses the
``client_secret`` in order to verify keys. This is simpler to implement, but
makes it harder to safely verify tokens.

Using ``HS256`` also means that you cannot use the Implicit or Hybrid flows,
or verify the tokens in public clients, because you cannot disclose the
``client_secret`` to a public client. If you are using a public client, you
must use ``RS256``.


Creating RSA private key
~~~~~~~~~~~~~~~~~~~~~~~~

To use ``RS256`` requires an RSA private key, which is used for signing JWT. You
can generate this using the `openssl`_ tool::

    openssl genrsa -out oidc.key 4096

This will generate a 4096-bit RSA key, which will be sufficient for our needs.

.. _openssl: https://www.openssl.org

.. warning::
    The contents of this key *must* be kept a secret. Don't put it in your
    settings and commit it to version control!

    If the key is ever accidentally disclosed, an attacker could use it to
    forge JWT tokens that verify as issued by your OAuth provider, which is
    very bad!

    If it is ever disclosed, you should immediately replace the key.

    Safe ways to handle it would be:

    * Store it in a secure system like `Hashicorp Vault`_, and inject it in to
      your environment when running your server.
    * Store it in a secure file on your server, and use your initialization
      scripts to inject it in to your environment.

.. _Hashicorp Vault: https://www.hashicorp.com/products/vault

Now we need to add this key to our settings and allow the ``openid`` scope to
be used. Assuming we have set an environment variable called
``OIDC_RSA_PRIVATE_KEY``, we can make changes to our ``settings.py``::

    import os.environ

    OAUTH2_PROVIDER = {
        "OIDC_ENABLED": True,
        "OIDC_RSA_PRIVATE_KEY": os.environ.get("OIDC_RSA_PRIVATE_KEY"),
        "SCOPES": {
            "openid": "OpenID Connect scope",
            # ... any other scopes that you use
        },
        # ... any other settings you want
    }

If you are adding OIDC support to an existing OAuth 2.0 provider site, and you
are currently using a custom class for ``OAUTH2_SERVER_CLASS``, you must
change this class to derive from ``oauthlib.openid.Server`` instead of
``oauthlib.oauth2.Server``.

With ``RSA`` key-pairs, the public key can be generated from the private key,
so there is no need to add a setting for the public key.

Using ``HS256`` keys
~~~~~~~~~~~~~~~~~~~~

If you would prefer to use just ``HS256`` keys, you don't need to create any
additional keys, ``django-oauth-toolkit`` will just use the application's
``client_secret`` to sign the JWT token.

In this case, you just need to enable OIDC and add ``openid`` to your list of
scopes in your ``settings.py``::

    OAUTH2_PROVIDER = {
        "OIDC_ENABLED": True,
        "SCOPES": {
            "openid": "OpenID Connect scope",
            # ... any other scopes that you use
        },
        # ... any other settings you want
    }

.. info::
    If you want to enable ``RS256`` at a later date, you can do so - just add
    the private key as described above.

Setting up OIDC enabled clients
===============================

Setting up an OIDC client in ``django-oauth-toolkit`` is simple - in fact, all
existing OAuth 2.0 Authorization Code Flow and Implicit Flow applications that
are already configured can be easily updated to use OIDC by setting the
appropriate algorithm for them to use.

You can also switch existing apps to use OIDC Hybrid Flow by changing their
Authorization Grant Type and selecting a signing algorithm to use.

You can read about the pros and cons of the different flows in `this excellent
article`_ from Robert Broeckelmann.

.. _this excellent article: https://medium.com/@robert.broeckelmann/when-to-use-which-oauth2-grants-and-oidc-flows-ec6a5c00d864

OIDC Authorization Code Flow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To create an OIDC Authorization Code Flow client, create an ``Application``
with the grant type ``Authorization code`` and select your desired signing
algorithm.

When making an authorization request, be sure to include ``openid`` as a
scope. When the code is exchanged for the access token, the response will
also contain an ID token JWT.

If the ``openid`` scope is not requested, authorization requests will be
treated as standard OAuth 2.0 Authorization Code Grant requests.

With ``PKCE`` enabled, even public clients can use this flow, and it is the most
secure and recommended flow.

OIDC Implicit Flow
~~~~~~~~~~~~~~~~~~

OIDC Implicit Flow is very similar to OAuth 2.0 Implicit Grant, except that
the client can request a ``response_type`` of ``id_token`` or ``id_token
token``. Requesting just ``token`` is also possible, but it would make it not
an OIDC flow and would fall back to being the same as OAuth 2.0 Implicit
Grant.

To setup an OIDC Implicit Flow client, simply create an ``Application`` with
the a grant type of ``Implicit`` and select your desired signing algorithm,
and configure the client to request the ``openid`` scope and an OIDC
``response_type`` (``id_token`` or ``id_token token``).


OIDC Hybrid Flow
~~~~~~~~~~~~~~~~

OIDC Hybrid Flow is a mixture of the previous two flows. It allows the ID
token and an access token to be returned to the frontend, whilst also
allowing the backend to retrieve the ID token and an access token (not
necessarily the same access token) on the backend.

To setup an OIDC Hybrid Flow application, create an ``Application`` with a
grant type of ``OpenID connect hybrid`` and select your desired signing
algorithm.


Customizing the OIDC responses
==============================

This basic configuration will give you a basic working OIDC setup, but your
ID tokens will have very few claims in them, and the ``UserInfo`` service will
just return the same claims as the ID token.

To configure all of these things we need to customize the
``OAUTH2_VALIDATOR_CLASS`` in ``django-oauth-toolkit``. Create a new file in
our project, eg ``my_project/oauth_validator.py``::

    from oauth2_provider.oauth2_validators import OAuth2Validator


    class CustomOAuth2Validator(OAuth2Validator):
        pass


and then configure our site to use this in our ``settings.py``::

    OAUTH2_PROVIDER = {
        "OAUTH2_VALIDATOR_CLASS": "my_project.oauth_validators.CustomOAuth2Validator",
        # ... other settings
    }

Now we can customize the tokens and the responses that are produced by adding
methods to our custom validator.


Adding claims to the ID token
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default the ID token will just have a ``sub`` claim (in addition to the
required claims, eg ``iss``, ``aud``, ``exp``, ``iat``, ``auth_time`` etc),
and the ``sub`` claim will use the primary key of the user as the value.
You'll probably want to customize this and add additional claims or change
what is sent for the ``sub`` claim. To do so, you will need to add a method to
our custom validator::

    class CustomOAuth2Validator(OAuth2Validator):

        def get_additional_claims(self, request):
            return {
                "sub": request.user.email,
                "first_name": request.user.first_name,
                "last_name": request.user.last_name,
            }

.. note::
    This ``request`` object is not a ``django.http.Request`` object, but an
    ``oauthlib.common.Request`` object. This has a number of attributes that
    you can use to decide what claims to put in to the ID token:

    * ``request.scopes`` - a list of the scopes requested by the client when
      making an authorization request.
    * ``request.claims`` - a dictionary of the requested claims, using the
      `OIDC claims requesting system`_. These must be requested by the client
      when making an authorization request.
    * ``request.user`` - the django user object.

.. _OIDC claims requesting system: https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter

What claims you decide to put in to the token is up to you to determine based
upon what the scopes and / or claims means to your provider.


Adding information to the ``UserInfo`` service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``UserInfo`` service is supplied as part of the OIDC service, and is used
to retrieve more information about the user than was supplied in the ID token
when the user logged in to the OIDC client application. It is optional to use
the service. The service is accessed by making a request to the
``UserInfo`` endpoint, eg ``/o/userinfo/`` and supplying the access token
retrieved at login as a ``Bearer`` token.

Again, to modify the content delivered, we need to add a function to our
custom validator. The default implementation adds the claims from the ID
token, so you will probably want to re-use that::

    class CustomOAuth2Validator(OAuth2Validator):

        def get_userinfo_claims(self, request):
            claims = super().get_userinfo_claims()
            claims["color_scheme"] = get_color_scheme(request.user)
            return claims


OIDC Views
==========

Enabling OIDC support adds three views to ``django-oauth-toolkit``. When OIDC
is not enabled, these views will log that OIDC support is not enabled, and
return a ``404`` response, or if ``DEBUG`` is enabled, raise an
``ImproperlyConfigured`` exception.

In the docs below, it assumes that you have mounted the
``django-oauth-toolkit`` at ``/o/``. If you have mounted it elsewhere, adjust
the URLs accordingly.


ConnectDiscoveryInfoView
~~~~~~~~~~~~~~~~~~~~~~~~

Available at ``/o/.well-known/openid-configuration/``, this view provides auto
discovery information to OIDC clients, telling them the JWT issuer to use, the
location of the JWKs to verify JWTs with, the token and userinfo endpoints to
query, and other details.


JwksInfoView
~~~~~~~~~~~~

Available at ``/o/.well-known/jwks.json``, this view provides details of the key used to sign
the JWTs generated for ID tokens, so that clients are able to verify them.


UserInfoView
~~~~~~~~~~~~

Available at ``/o/userinfo/``, this view provides extra user details. You can
customize the details included in the response as described above.
