.. Put definition of specific terms here, and reference them inside docs with :term:`My term` syntax

.. glossary::

    Authorization Server
        The authorization server asks resource owners for their consensus to let client applications access their data.
        It also manages and issues the tokens needed for all the authorization flows supported by OAuth2 protocol.
        Usually the same application offering resources through an OAuth2-protected API also behaves like an
        authorization server.

    Application
    Client
        A client is an application authorized to access OAuth2-protected resources on behalf and with the authorization
        of the resource owner.

    Resource Owner
        The user of an application which exposes resources to third party applications through the OAuth2 protocol. The
        resource owner must give her authorization for third party applications to be able to access her data.