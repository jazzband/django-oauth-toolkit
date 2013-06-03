# urlparse in python3 has been renamed to urllib.parse
try:
    from urlparse import urlparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, parse_qs
