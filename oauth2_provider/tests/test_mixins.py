from __future__ import unicode_literals

from django.core.exceptions import ImproperlyConfigured
from django.views.generic import View
from django.test import TestCase, RequestFactory

from oauthlib.oauth2 import Server

from ..views.mixins import OAuthLibMixin, ScopedResourceMixin
from ..oauth2_validators import OAuth2Validator


class TestOAuthLibMixin(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.request_factory = RequestFactory()

    def test_missing_server_class(self):
        class TestView(OAuthLibMixin, View):
            validator_class = OAuth2Validator

        test_view = TestView()

        self.assertRaises(ImproperlyConfigured, test_view.get_server)

    def test_missing_validator_class(self):
        class TestView(OAuthLibMixin, View):
            server_class = Server

        test_view = TestView()

        self.assertRaises(ImproperlyConfigured, test_view.get_server)

    def test_correct_server(self):
        class TestView(OAuthLibMixin, View):
            server_class = Server
            validator_class = OAuth2Validator

        request = self.request_factory.get("/fake-req")
        request.user = "fake"
        test_view = TestView()

        self.assertIsInstance(test_view.get_server(), Server)

    def test_custom_backend(self):
        class AnotherOauthLibBackend(object):
            pass

        class TestView(OAuthLibMixin, View):
            server_class = Server
            validator_class = OAuth2Validator
            oauthlib_core_class = AnotherOauthLibBackend

        request = self.request_factory.get("/fake-req")
        request.user = "fake"
        test_view = TestView()

        self.assertEqual(test_view.get_oauthlib_core_class(),
                         AnotherOauthLibBackend)


class TestScopedResourceMixin(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.request_factory = RequestFactory()

    def test_missing_required_scopes(self):
        class TestView(ScopedResourceMixin, View):
            pass

        test_view = TestView()

        self.assertRaises(ImproperlyConfigured, test_view.get_scopes)

    def test_correct_required_scopes(self):
        class TestView(ScopedResourceMixin, View):
            required_scopes = ['scope1', 'scope2']

        test_view = TestView()

        self.assertEqual(test_view.get_scopes(), ['scope1', 'scope2'])
