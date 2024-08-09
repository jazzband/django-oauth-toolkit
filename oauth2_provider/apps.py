from django.apps import AppConfig, apps
from django.core.exceptions import ImproperlyConfigured
from django.db import router


class DOTConfig(AppConfig):
    name = "oauth2_provider"
    verbose_name = "Django OAuth Toolkit"

    def _validate_token_configuration(self):
        from .settings import oauth2_settings

        databases = set(
            router.db_for_write(apps.get_model(model))
            for model in (
                oauth2_settings.ACCESS_TOKEN_MODEL,
                oauth2_settings.ID_TOKEN_MODEL,
                oauth2_settings.REFRESH_TOKEN_MODEL,
            )
        )

        # This is highly unlikely, but let's warn people just in case it does.
        # If the tokens were allowed to be in different databases this would require all
        # writes to have a transaction around each database. Instead, let's enforce that
        # they all live together in one database.
        # The tokens are not required to live in the default database provided the Django
        # routers know the correct database for them.
        if len(databases) > 1:
            raise ImproperlyConfigured("the token models are expected to be stored in the same database.")

    def ready(self):
        self._validate_token_configuration()
