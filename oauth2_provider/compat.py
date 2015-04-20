"""
The `compat` module provides support for backwards compatibility with older
versions of django and python..
"""

from __future__ import unicode_literals

import django
from django.conf import settings

# urlparse in python3 has been renamed to urllib.parse
try:
    from urlparse import urlparse, parse_qs, parse_qsl, urlunparse
except ImportError:
    from urllib.parse import urlparse, parse_qs, parse_qsl, urlunparse

try:
    from urllib import urlencode, unquote_plus
except ImportError:
    from urllib.parse import urlencode, unquote_plus

# Django 1.5 add support for custom auth user model
if django.VERSION >= (1, 5):
    AUTH_USER_MODEL = settings.AUTH_USER_MODEL
else:
    AUTH_USER_MODEL = 'auth.User'

try:
    from django.contrib.auth import get_user_model
except ImportError:
    from django.contrib.auth.models import User
    get_user_model = lambda: User

# Django's new application loading system
try:
    from django.apps import apps
    get_model = apps.get_model
except ImportError:
    from django.db.models import get_model
