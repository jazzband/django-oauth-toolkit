import django


__version__ = "1.6.2"

if django.VERSION < (3, 2):
    default_app_config = "oauth2_provider.apps.DOTConfig"
