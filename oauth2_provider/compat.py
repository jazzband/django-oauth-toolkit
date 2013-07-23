"""
The `compat` module provides support for backwards compatibility with older
versions of django and python..
"""

from __future__ import unicode_literals

import django
from django.conf import settings

# urlparse in python3 has been renamed to urllib.parse
try:
    from urlparse import urlparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, parse_qs

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

# Django 1.5 add support for custom auth user model
if django.VERSION >= (1, 5):
    AUTH_USER_MODEL = settings.AUTH_USER_MODEL
else:
    AUTH_USER_MODEL = 'auth.User'
