import django


__version__ = "2.1.0"

if django.VERSION < (3, 2):
    default_app_config = "oauth2_provider.apps.DOTConfig"
