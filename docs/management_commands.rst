Management commands
===================

Django OAuth Toolkit exposes some useful management commands that can be run via shell or by other means such as cron
or :doc:`Celery <tutorial/tutorial_05>`.

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

.. code-block:: sh

    usage: manage.py createapplication [-h] [--client-id CLIENT_ID] [--user USER] [--redirect-uris REDIRECT_URIS]
				       [--client-secret CLIENT_SECRET] [--name NAME] [--skip-authorization] [--version] [-v {0,1,2,3}]
				       [--settings SETTINGS] [--pythonpath PYTHONPATH] [--traceback] [--no-color] [--force-color]
				       [--skip-checks]
				       client_type authorization_grant_type

    Shortcut to create a new application in a programmatic way

    positional arguments:
      client_type           The client type, can be confidential or public
      authorization_grant_type
			    The type of authorization grant to be used

    optional arguments:
      -h, --help            show this help message and exit
      --client-id CLIENT_ID
			    The ID of the new application
      --user USER           The user the application belongs to
      --redirect-uris REDIRECT_URIS
			    The redirect URIs, this must be a space separated string e.g 'URI1 URI2'
      --client-secret CLIENT_SECRET
			    The secret for this application
      --name NAME           The name this application
      --skip-authorization  The ID of the new application
      ...
