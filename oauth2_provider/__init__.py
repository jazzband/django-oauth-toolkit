try:
    from importlib.metadata import version
except ImportError:
    from importlib_metadata import version


__version__ = version("django-oauth-toolkit")

default_app_config = "oauth2_provider.apps.DOTConfig"
