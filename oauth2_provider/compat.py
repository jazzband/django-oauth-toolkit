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
import django
if django.VERSION >= (1, 5):
    from django.conf import settings
    if hasattr(settings, 'AUTH_USER_MODEL'):
        from django.contrib.auth import get_user_model
        User = get_user_model()
    else:
        from django.contrib.auth.models import User
else:
    try:
        from django.contrib.auth.models import User
    except ImportError:
        raise ImportError("User model is not to be found.")