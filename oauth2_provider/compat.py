"""
The `compat` module provides support for backwards compatibility with older
versions of django and python..
"""

from __future__ import unicode_literals

from django.conf import settings
from django.db.models import get_model
from django.contrib.auth import models
from django.core.exceptions import ImproperlyConfigured

# urlparse in python3 has been renamed to urllib.parse
try:
    from urlparse import urlparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, parse_qs

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

def get_user_model():
    "Return the User model that is active in this project"
    auth_user_model = getattr(settings, 'AUTH_USER_MODEL', '') or models.User
    _AUTH_USER_MODEL = getattr(settings, 'OAUTH2_USER_MODEL', '') or auth_user_model

    try:
        app_label, model_name = _AUTH_USER_MODEL.split('.')
    except ValueError:
        raise ImproperlyConfigured("OAUTH2_USER_MODEL or AUTH_USER_MODEL must be of the form 'app_label.model_name'")
    user_model = get_model(app_label, model_name)
    if user_model is None:
        raise ImproperlyConfigured(
            "OAUTH2_USER_MODEL or AUTH_USER_MODEL refers to model '%s' that has not been installed" % _AUTH_USER_MODEL)
    return user_model

_auth_user_model = getattr(settings, 'AUTH_USER_MODEL', '') or models.User
AUTH_USER_MODEL = getattr(settings, 'OAUTH2_USER_MODEL', '') or _auth_user_model
