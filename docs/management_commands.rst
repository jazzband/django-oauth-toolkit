Management commands
===================

Django OAuth Toolkit exposes some useful management commands that can be run via shell or by other means (eg: cron)

.. _cleartokens:

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

The ``cleartokens`` action can also be scheduled as a `Celery periodic task`_
by using the ``clear_tokens`` task (automatically registered when using Celery).

.. _Celery periodic task: https://docs.celeryproject.org/en/stable/userguide/periodic-tasks.html
