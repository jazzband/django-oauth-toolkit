Separate Resource Server
========================
Django OAuth Toolkit allows to separate the :term:`Authentication Server` and the :term:`Resource Server.`
Based one the `RFC 7662 <https://tools.ietf.org/html/rfc7662>`_ Django OAuth Toolkit provides
a rfc-compliant introspection endpoint.
As well the Django OAuth Toolkit allows to verify access tokens by the use of an introspection endpoint.


Setup the Authentication Server
-------------------------------
Setup the :term:`Authentication Server` as described in the :ref:`tutorial`.
Create a OAuth2 access token for the :term:`Resource Server` and add the
``introspection``-Scope to the settings.

.. code-block:: python

    'SCOPES': {
        'read': 'Read scope',
        'write': 'Write scope',
        'introspection': 'Introspect token scope',
        ...
    },

The :term:`Authentication Server` will listen for introspection requests.
The endpoint is located within the ``oauth2_provider.urls`` as ``/introspect/``.

Example Request::

    POST /o/introspect/ HTTP/1.1
    Host: server.example.com
    Accept: application/json
    Content-Type: application/x-www-form-urlencoded
    Authorization: Bearer 3yUqsWtwKYKHnfivFcJu

    token=uH3Po4KXWP4dsY4zgyxH

Example Response::

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "active": true,
      "client_id": "oUdofn7rfhRtKWbmhyVk",
      "username": "jdoe",
      "scope": "read write dolphin",
      "exp": 1419356238
    }

Setup the Resource Server
-------------------------
Setup the :term:`Resource Server` like the :term:`Authentication Server` as described in the :ref:`tutorial`.
Add ``RESOURCE_SERVER_INTROSPECTION_URL`` and ``RESOURCE_SERVER_AUTH_TOKEN`` to your settings.
The :term:`Resource Server` will try to verify its requests on the :term:`Authentication Server`.

.. code-block:: python

    OAUTH2_PROVIDER = {
        ...
        'RESOURCE_SERVER_INTROSPECTION_URL': 'https://example.org/o/introspect/',
        'RESOURCE_SERVER_AUTH_TOKEN': '3yUqsWtwKYKHnfivFcJu',
        ...
    }

``RESOURCE_SERVER_INTROSPECTION_URL`` defines the introspection endpoint and
``RESOURCE_SERVER_AUTH_TOKEN`` an authentication token to authenticate against the
:term:`Authentication Server`.

