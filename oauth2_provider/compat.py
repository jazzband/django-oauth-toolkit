"""
The `compat` module provides support for backwards compatibility with older
versions of django and python.
"""
# flake8: noqa
from __future__ import unicode_literals

# urlparse in python3 has been renamed to urllib.parse
try:
    from urlparse import urlparse, parse_qs, parse_qsl, urlunparse
except ImportError:
    from urllib.parse import urlparse, parse_qs, parse_qsl, urlunparse

try:
    from urllib import urlencode, unquote_plus
except ImportError:
    from urllib.parse import urlencode, unquote_plus

# changed in Django 1.10 (broken in Django 2.0)
try:
    from django.urls import reverse, reverse_lazy
except ImportError:
    from django.core.urlresolvers import reverse, reverse_lazy

# bastb Django 1.10 has updated Middleware. This code imports the Mixin required to get old-style
# middleware working again
# More?
#  https://docs.djangoproject.com/en/1.10/topics/http/middleware/#upgrading-pre-django-1-10-style-middleware
try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:
    MiddlewareMixin = object
