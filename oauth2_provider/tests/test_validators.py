from __future__ import unicode_literals

from django.test import TestCase
from django.core.validators import ValidationError

from ..validators import validate_uris


class TestValidators(TestCase):
    def test_validate_good_uris(self):
        good_urls = 'http://example.com/ http://example.it/?key=val http://example'
        # Check ValidationError not thrown
        validate_uris(good_urls)

    def test_validate_bad_uris(self):
        bad_url = 'http://example.com/#fragment'
        self.assertRaises(ValidationError, validate_uris, bad_url)
        bad_url = 'http:/example.com'
        self.assertRaises(ValidationError, validate_uris, bad_url)