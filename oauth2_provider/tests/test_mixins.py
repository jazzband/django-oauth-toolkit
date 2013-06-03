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

        request = self.request_factory.get("/fake-req")
        test_view = TestView()

        self.assertRaises(ImproperlyConfigured, test_view.get_server, request)

    def test_missing_validator_class(self):
        class TestView(OAuthLibMixin, View):
            server_class = Server

        request = self.request_factory.get("/fake-req")
        test_view = TestView()

        self.assertRaises(ImproperlyConfigured, test_view.get_server, request)

    def test_correct_server(self):
        class TestView(OAuthLibMixin, View):
            server_class = Server
            validator_class = OAuth2Validator

        request = self.request_factory.get("/fake-req")
        request.user = "fake"
        test_view = TestView()

        self.assertIsInstance(test_view.get_server(request), Server)


class TestScopedResourceMixin(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.request_factory = RequestFactory()

    def test_missing_requested_scopes(self):
        class TestView(ScopedResourceMixin, View):
            pass

        request = self.request_factory.get("/fake-req")
        test_view = TestView()

        self.assertRaises(ImproperlyConfigured, test_view.get_scopes)

    def test_correct_requested_scopes(self):
        class TestView(ScopedResourceMixin, View):
            requested_scopes = ['scope1', 'scope2']

        request = self.request_factory.get("/fake-req")
        test_view = TestView()

        self.assertEqual(test_view.get_scopes(), ['scope1', 'scope2'])
