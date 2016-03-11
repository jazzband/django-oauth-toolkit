from __future__ import unicode_literals

from django.core.exceptions import ImproperlyConfigured
from django.views.generic import View
from django.test import TestCase, RequestFactory

from oauthlib.oauth2 import Server

from ..views.mixins import OAuthLibMixin, ScopedResourceMixin, ProtectedResourceMixin
from ..oauth2_backends import OAuthLibCore
from ..oauth2_validators import OAuth2Validator


class BaseTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.request_factory = RequestFactory()
        super(BaseTest, cls).setUpClass()


class TestOAuthLibMixin(BaseTest):
    def test_missing_oauthlib_backend_class(self):
        class TestView(OAuthLibMixin, View):
            server_class = Server
            validator_class = OAuth2Validator

        test_view = TestView()

        self.assertRaises(ImproperlyConfigured, test_view.get_oauthlib_backend_class)

    def test_missing_server_class(self):
        class TestView(OAuthLibMixin, View):
            validator_class = OAuth2Validator
            oauthlib_backend_class = OAuthLibCore

        test_view = TestView()

        self.assertRaises(ImproperlyConfigured, test_view.get_server)

    def test_missing_validator_class(self):
        class TestView(OAuthLibMixin, View):
            server_class = Server
            oauthlib_backend_class = OAuthLibCore

        test_view = TestView()

        self.assertRaises(ImproperlyConfigured, test_view.get_server)

    def test_correct_server(self):
        class TestView(OAuthLibMixin, View):
            server_class = Server
            validator_class = OAuth2Validator
            oauthlib_backend_class = OAuthLibCore

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
            oauthlib_backend_class = AnotherOauthLibBackend

        request = self.request_factory.get("/fake-req")
        request.user = "fake"
        test_view = TestView()

        self.assertEqual(test_view.get_oauthlib_backend_class(),
                         AnotherOauthLibBackend)


class TestScopedResourceMixin(BaseTest):
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


class TestProtectedResourceMixin(BaseTest):
    def test_options_shall_pass(self):
        class TestView(ProtectedResourceMixin, View):
            server_class = Server
            validator_class = OAuth2Validator

        request = self.request_factory.options("/fake-req")
        view = TestView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 200)
