"""
The `compat` module provides support for backwards compatibility with older
versions of django and python.
"""
# flake8: noqa
from __future__ import unicode_literals

# urlparse in python3 has been renamed to urllib.parse
try:
    from urlparse import parse_qs, parse_qsl, urlparse, urlsplit, urlunparse, urlunsplit
except ImportError:
    from urllib.parse import parse_qs, parse_qsl, urlparse, urlsplit, urlunsplit, urlunparse

try:
    from urllib import urlencode, quote_plus, unquote_plus
except ImportError:
    from urllib.parse import urlencode, quote_plus, unquote_plus

# bastb Django 1.10 has updated Middleware. This code imports the Mixin required to get old-style
# middleware working again
# More?
#  https://docs.djangoproject.com/en/1.10/topics/http/middleware/#upgrading-pre-django-1-10-style-middleware
try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:
    MiddlewareMixin = object
