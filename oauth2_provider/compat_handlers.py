# flake8: noqa
# Django 1.9 drops the NullHandler since Python 2.7 includes it
try:
    from logging import NullHandler
except ImportError:
    from django.utils.log import NullHandler
