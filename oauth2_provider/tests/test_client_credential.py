from __future__ import unicode_literals

import json

try:
    import urllib.parse as urllib
except ImportError:
    import urllib

from django.contrib.auth import get_user_model
from django.test import TestCase, RequestFactory
from django.views.generic import View

from oauthlib.oauth2 import BackendApplicationServer

from ..compat import reverse
from ..models import get_application_model, AccessToken
from ..oauth2_backends import OAuthLibCore
from ..oauth2_validators import OAuth2Validator
from ..settings import oauth2_settings
from ..views import ProtectedResourceView
from ..views.mixins import OAuthLibMixin
from .test_utils import TestCaseUtils


Application = get_application_model()
UserModel = get_user_model()


# mocking a protected resource view
class ResourceView(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


class BaseTest(TestCaseUtils, TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.test_user = UserModel.objects.create_user("test_user", "test@user.com", "123456")
        self.dev_user = UserModel.objects.create_user("dev_user", "dev@user.com", "123456")

        self.application = Application(
            name="test_client_credentials_app",
            user=self.dev_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
        )
        self.application.save()

        oauth2_settings._SCOPES = ['read', 'write']
        oauth2_settings._DEFAULT_SCOPES = ['read', 'write']

    def tearDown(self):
        self.application.delete()
        self.test_user.delete()
        self.dev_user.delete()


class TestClientCredential(BaseTest):
    def test_client_credential_access_allowed(self):
        """
        Request an access token using Client Credential Flow
        """
        token_request_data = {
            'grant_type': 'client_credentials',
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        access_token = content['access_token']

        # use token to access the resource
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")

    def test_client_credential_does_not_issue_refresh_token(self):
        token_request_data = {
            'grant_type': 'client_credentials',
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertNotIn("refresh_token", content)

    def test_client_credential_user_is_none_on_access_token(self):
        token_request_data = {'grant_type': 'client_credentials'}
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        access_token = AccessToken.objects.get(token=content["access_token"])
        self.assertIsNone(access_token.user)


class TestExtendedRequest(BaseTest):
    @classmethod
    def setUpClass(cls):
        cls.request_factory = RequestFactory()
        super(TestExtendedRequest, cls).setUpClass()

    def test_extended_request(self):
        class TestView(OAuthLibMixin, View):
            server_class = BackendApplicationServer
            validator_class = OAuth2Validator
            oauthlib_backend_class = OAuthLibCore

            def get_scopes(self):
                return ['read', 'write']

        token_request_data = {
            'grant_type': 'client_credentials',
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)
        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        access_token = content['access_token']

        # use token to access the resource
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }

        request = self.request_factory.get("/fake-req", **auth_headers)
        request.user = "fake"

        test_view = TestView()
        self.assertIsInstance(test_view.get_server(), BackendApplicationServer)

        valid, r = test_view.verify_request(request)
        self.assertTrue(valid)
        self.assertIsNone(r.user)
        self.assertEqual(r.client, self.application)
        self.assertEqual(r.scopes, ['read', 'write'])


class TestClientResourcePasswordBased(BaseTest):
    def test_client_resource_password_based(self):
        """
        Request an access token using Resource Owner Password Based flow
        """

        self.application.delete()
        self.application = Application(
            name="test_client_credentials_app",
            user=self.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
        )
        self.application.save()

        token_request_data = {
            'grant_type': 'password',
            'username': 'test_user',
            'password': '123456'
        }
        auth_headers = self.get_basic_auth_header(
            urllib.quote_plus(self.application.client_id),
            urllib.quote_plus(self.application.client_secret))

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        access_token = content['access_token']

        # use token to access the resource
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")
