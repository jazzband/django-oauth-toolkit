Management commands
===================

Django OAuth Toolkit exposes some useful management commands that can be run via shell or by other means (eg: cron)

.. _cleartokens:
.. _createapplication:


cleartokens
~~~~~~~~~~~

The ``cleartokens`` management command allows the user to remove those refresh tokens whose lifetime is greater than the
amount specified by ``REFRESH_TOKEN_EXPIRE_SECONDS`` settings. It is important that this command is run regularly
(eg: via cron) to avoid cluttering the database with expired refresh tokens.

If ``cleartokens`` runs daily the maximum delay before a refresh token is
removed is ``REFRESH_TOKEN_EXPIRE_SECONDS`` + 1 day. This is normally not a
problem since refresh tokens are long lived.

To prevent the CPU and RAM high peaks during deletion process use ``CLEAR_EXPIRED_TOKENS_BATCH_SIZE`` and
``CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL`` settings to adjust the process speed.

Note: Refresh tokens need to expire before AccessTokens can be removed from the
database. Using ``cleartokens`` without ``REFRESH_TOKEN_EXPIRE_SECONDS`` has limited effect.



createapplication
~~~~~~~~~~~~~~~~~

The ``createapplication`` management command provides a shortcut to create a new application in a programmatic way.

This command is used like this:

.. code-block:: sh

    python3 manage.py createapplication [arguments] <client_type> <authorization_grant_type>


This command provides the following arguments:

+----------------------------+------+-------------------------------------------------------------------------------------------------+
|          Argument          | type |                                           Description                                           |
+============================+======+=================================================================================================+
| `--client_id`              | str  | The ID of the new application                                                                   |
+----------------------------+------+-------------------------------------------------------------------------------------------------+
| `--user`                   | int  | The ID of the user that the application belongs to                                              |
+----------------------------+------+-------------------------------------------------------------------------------------------------+
| `--redirect-uris`          | str  | The redirect URIs. This must be a space-separated string (e.g., `"https://uri1/ https://uri2"`) |
+----------------------------+------+-------------------------------------------------------------------------------------------------+
| `--name`                   | str  | The name of this application                                                                    |
+----------------------------+------+-------------------------------------------------------------------------------------------------+
| `--skip-authorization`     | flag | If set, completely bypass the authorization form, even on the first use of the application      |
+----------------------------+------+-------------------------------------------------------------------------------------------------+
| `--algorithm`              | str  | The OIDC token signing algorithm for this application (e.g., `RS256` or `HS256`)                |
+----------------------------+------+-------------------------------------------------------------------------------------------------+
| `client_type`              | str  | The client type, can be `confidential` or `public`                                              |
+----------------------------+------+-------------------------------------------------------------------------------------------------+
| `authorization_grant_type` | str  | The type of authorization grant to be used                                                      |
+----------------------------+------+-------------------------------------------------------------------------------------------------+
