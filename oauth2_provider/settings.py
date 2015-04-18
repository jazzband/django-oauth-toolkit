"""
This module is largely inspired by django-rest-framework settings.

Settings for the OAuth2 Provider are all namespaced in the OAUTH2_PROVIDER setting.
For example your project's `settings.py` file might look like this:

OAUTH2_PROVIDER = {
    'CLIENT_ID_GENERATOR_CLASS':
        'oauth2_provider.generators.ClientIdGenerator',
    'CLIENT_SECRET_GENERATOR_CLASS':
        'oauth2_provider.generators.ClientSecretGenerator',
}

This module provides the `oauth2_settings` object, that is used to access
OAuth2 Provider settings, checking for user settings first, then falling
back to the defaults.
"""
from __future__ import unicode_literals

import six

from django.conf import settings
try:
    # Available in Python 2.7+
    import importlib
except ImportError:
    from django.utils import importlib


USER_SETTINGS = getattr(settings, 'OAUTH2_PROVIDER', None)

DEFAULTS = {
    'CLIENT_ID_GENERATOR_CLASS': 'oauth2_provider.generators.ClientIdGenerator',
    'CLIENT_SECRET_GENERATOR_CLASS': 'oauth2_provider.generators.ClientSecretGenerator',
    'CLIENT_SECRET_GENERATOR_LENGTH': 128,
    'OAUTH2_VALIDATOR_CLASS': 'oauth2_provider.oauth2_validators.OAuth2Validator',
    'OAUTH2_BACKEND_CLASS': 'oauth2_provider.oauth2_backends.OAuthLibCore',
    'SCOPES': {"read": "Reading scope", "write": "Writing scope"},
    'READ_SCOPE': 'read',
    'WRITE_SCOPE': 'write',
    'AUTHORIZATION_CODE_EXPIRE_SECONDS': 60,
    'ACCESS_TOKEN_EXPIRE_SECONDS': 36000,
    'APPLICATION_MODEL': getattr(settings, 'OAUTH2_PROVIDER_APPLICATION_MODEL', 'oauth2_provider.Application'),
    'REQUEST_APPROVAL_PROMPT': 'force',
    'ALLOWED_REDIRECT_URI_SCHEMES': ['http', 'https'],

    # Special settings that will be evaluated at runtime
    '_SCOPES': [],
}

# List of settings that cannot be empty
MANDATORY = (
    'CLIENT_ID_GENERATOR_CLASS',
    'CLIENT_SECRET_GENERATOR_CLASS',
    'OAUTH2_VALIDATOR_CLASS',
    'OAUTH2_BACKEND_CLASS',
    'SCOPES',
    'ALLOWED_REDIRECT_URI_SCHEMES',
)

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'CLIENT_ID_GENERATOR_CLASS',
    'CLIENT_SECRET_GENERATOR_CLASS',
    'OAUTH2_VALIDATOR_CLASS',
    'OAUTH2_BACKEND_CLASS',
)


def perform_import(val, setting_name):
    """
    If the given setting is a string import notation,
    then perform the necessary import or imports.
    """
    if isinstance(val, six.string_types):
        return import_from_string(val, setting_name)
    elif isinstance(val, (list, tuple)):
        return [import_from_string(item, setting_name) for item in val]
    return val


def import_from_string(val, setting_name):
    """
    Attempt to import a class from a string representation.
    """
    try:
        parts = val.split('.')
        module_path, class_name = '.'.join(parts[:-1]), parts[-1]
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    except ImportError as e:
        msg = "Could not import '%s' for setting '%s'. %s: %s." % (val, setting_name, e.__class__.__name__, e)
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
            raise AttributeError("Invalid OAuth2Provider setting: '%s'" % attr)

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
        if attr == '_SCOPES':
            val = list(six.iterkeys(self.SCOPES))

        self.validate_setting(attr, val)

        # Cache the result
        setattr(self, attr, val)
        return val

    def validate_setting(self, attr, val):
        if not val and attr in self.mandatory:
            raise AttributeError("OAuth2Provider setting: '%s' is mandatory" % attr)


oauth2_settings = OAuth2ProviderSettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS, MANDATORY)
