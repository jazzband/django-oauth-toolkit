"""
This module is largely inspired by django-rest-framework settings.

Settings for the OAuth2 Provider are all namespaced in the OAUTH2_PROVIDER setting.
For example your project's `settings.py` file might look like this:

OAUTH2_PROVIDER = {
    "CLIENT_ID_GENERATOR_CLASS":
        "oauth2_provider.generators.ClientIdGenerator",
    "CLIENT_SECRET_GENERATOR_CLASS":
        "oauth2_provider.generators.ClientSecretGenerator",
}

This module provides the `oauth2_settings` object, that is used to access
OAuth2 Provider settings, checking for user settings first, then falling
back to the defaults.
"""
import importlib

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


USER_SETTINGS = getattr(settings, "OAUTH2_PROVIDER", None)

APPLICATION_MODEL = getattr(settings, "OAUTH2_PROVIDER_APPLICATION_MODEL", "oauth2_provider.Application")
ACCESS_TOKEN_MODEL = getattr(settings, "OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL", "oauth2_provider.AccessToken")
GRANT_MODEL = getattr(settings, "OAUTH2_PROVIDER_GRANT_MODEL", "oauth2_provider.Grant")
REFRESH_TOKEN_MODEL = getattr(settings, "OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL", "oauth2_provider.RefreshToken")

DEFAULTS = {
    "CLIENT_ID_GENERATOR_CLASS": "oauth2_provider.generators.ClientIdGenerator",
    "CLIENT_SECRET_GENERATOR_CLASS": "oauth2_provider.generators.ClientSecretGenerator",
    "CLIENT_SECRET_GENERATOR_LENGTH": 128,
    "ACCESS_TOKEN_GENERATOR": None,
    "REFRESH_TOKEN_GENERATOR": None,
    "EXTRA_SERVER_KWARGS": {},
    "OAUTH2_SERVER_CLASS": "oauthlib.oauth2.Server",
    "OAUTH2_VALIDATOR_CLASS": "oauth2_provider.oauth2_validators.OAuth2Validator",
    "OAUTH2_BACKEND_CLASS": "oauth2_provider.oauth2_backends.OAuthLibCore",
    "SCOPES": {"read": "Reading scope", "write": "Writing scope"},
    "DEFAULT_SCOPES": ["__all__"],
    "SCOPES_BACKEND_CLASS": "oauth2_provider.scopes.SettingsScopes",
    "READ_SCOPE": "read",
    "WRITE_SCOPE": "write",
    "AUTHORIZATION_CODE_EXPIRE_SECONDS": 60,
    "ACCESS_TOKEN_EXPIRE_SECONDS": 36000,
    "REFRESH_TOKEN_EXPIRE_SECONDS": None,
    "REFRESH_TOKEN_GRACE_PERIOD_SECONDS": 0,
    "ROTATE_REFRESH_TOKEN": True,
    "ERROR_RESPONSE_WITH_SCOPES": False,
    "APPLICATION_MODEL": APPLICATION_MODEL,
    "ACCESS_TOKEN_MODEL": ACCESS_TOKEN_MODEL,
    "GRANT_MODEL": GRANT_MODEL,
    "REFRESH_TOKEN_MODEL": REFRESH_TOKEN_MODEL,
    "REQUEST_APPROVAL_PROMPT": "force",
    "ALLOWED_REDIRECT_URI_SCHEMES": ["http", "https"],

    # Special settings that will be evaluated at runtime
    "_SCOPES": [],
    "_DEFAULT_SCOPES": [],

    # Resource Server with Token Introspection
    "RESOURCE_SERVER_INTROSPECTION_URL": None,
    "RESOURCE_SERVER_AUTH_TOKEN": None,
    "RESOURCE_SERVER_INTROSPECTION_CREDENTIALS": None,
    "RESOURCE_SERVER_TOKEN_CACHING_SECONDS": 36000,

    # Whether or not PKCE is required
    "PKCE_REQUIRED": False
}

# List of settings that cannot be empty
MANDATORY = (
    "CLIENT_ID_GENERATOR_CLASS",
    "CLIENT_SECRET_GENERATOR_CLASS",
    "OAUTH2_SERVER_CLASS",
    "OAUTH2_VALIDATOR_CLASS",
    "OAUTH2_BACKEND_CLASS",
    "SCOPES",
    "ALLOWED_REDIRECT_URI_SCHEMES",
)

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    "CLIENT_ID_GENERATOR_CLASS",
    "CLIENT_SECRET_GENERATOR_CLASS",
    "ACCESS_TOKEN_GENERATOR",
    "REFRESH_TOKEN_GENERATOR",
    "OAUTH2_SERVER_CLASS",
    "OAUTH2_VALIDATOR_CLASS",
    "OAUTH2_BACKEND_CLASS",
    "SCOPES_BACKEND_CLASS",
)


def perform_import(val, setting_name):
    """
    If the given setting is a string import notation,
    then perform the necessary import or imports.
    """
    if isinstance(val, (list, tuple)):
        return [import_from_string(item, setting_name) for item in val]
    elif "." in val:
        return import_from_string(val, setting_name)
    else:
        raise ImproperlyConfigured("Bad value for %r: %r" % (setting_name, val))


def import_from_string(val, setting_name):
    """
    Attempt to import a class from a string representation.
    """
    try:
        parts = val.split(".")
        module_path, class_name = ".".join(parts[:-1]), parts[-1]
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    except ImportError as e:
        msg = "Could not import %r for setting %r. %s: %s." % (val, setting_name, e.__class__.__name__, e)
        raise ImportError(msg)


class OAuth2ProviderSettings(object):
    """
    A settings object, that allows OAuth2 Provider settings to be accessed as properties.

    Any setting with string import paths will be automatically resolved
    and return the class, rather than the string literal.
    """

    def __init__(self, user_settings=None, defaults=None, import_strings=None, mandatory=None):
        self.user_settings = user_settings or {}
        self.defaults = defaults or {}
        self.import_strings = import_strings or ()
        self.mandatory = mandatory or ()

    def __getattr__(self, attr):
        if attr not in self.defaults.keys():
            raise AttributeError("Invalid OAuth2Provider setting: %r" % (attr))

        try:
            # Check if present in user settings
            val = self.user_settings[attr]
        except KeyError:
            # Fall back to defaults
            val = self.defaults[attr]

        # Coerce import strings into classes
        if val and attr in self.import_strings:
            val = perform_import(val, attr)

        # Overriding special settings
        if attr == "_SCOPES":
            val = list(self.SCOPES.keys())
        if attr == "_DEFAULT_SCOPES":
            if "__all__" in self.DEFAULT_SCOPES:
                # If DEFAULT_SCOPES is set to ["__all__"] the whole set of scopes is returned
                val = list(self._SCOPES)
            else:
                # Otherwise we return a subset (that can be void) of SCOPES
                val = []
                for scope in self.DEFAULT_SCOPES:
                    if scope in self._SCOPES:
                        val.append(scope)
                    else:
                        raise ImproperlyConfigured("Defined DEFAULT_SCOPES not present in SCOPES")

        self.validate_setting(attr, val)

        # Cache the result
        setattr(self, attr, val)
        return val

    def validate_setting(self, attr, val):
        if not val and attr in self.mandatory:
            raise AttributeError("OAuth2Provider setting: %r is mandatory" % (attr))

    @property
    def server_kwargs(self):
        """
        This is used to communicate settings to oauth server.

        Takes relevant settings and format them accordingly.
        There's also EXTRA_SERVER_KWARGS that can override every value
        and is more flexible regarding keys and acceptable values
        but doesn't have import string magic or any additional
        processing, callables have to be assigned directly.
        For the likes of signed_token_generator it means something like

        {"token_generator": signed_token_generator(privkey, **kwargs)}
        """
        kwargs = {
            key: getattr(self, value)
            for key, value in [
                ("token_expires_in", "ACCESS_TOKEN_EXPIRE_SECONDS"),
                ("refresh_token_expires_in", "REFRESH_TOKEN_EXPIRE_SECONDS"),
                ("token_generator", "ACCESS_TOKEN_GENERATOR"),
                ("refresh_token_generator", "REFRESH_TOKEN_GENERATOR"),
            ]
        }
        kwargs.update(self.EXTRA_SERVER_KWARGS)
        return kwargs


oauth2_settings = OAuth2ProviderSettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS, MANDATORY)
