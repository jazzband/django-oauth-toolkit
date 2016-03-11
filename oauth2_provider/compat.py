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
