from __future__ import unicode_literals

import json

from django.test import TestCase, RequestFactory
from django.core.urlresolvers import reverse

from ..compat import User
from ..models import Application
from ..settings import oauth2_settings
from ..views import ProtectedResourceView

from .test_utils import TestCaseUtils


# mocking a protected resource view
class ResourceView(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


class BaseTest(TestCaseUtils, TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.test_user = User.objects.create_user("test_user", "test@user.com", "123456")
        self.dev_user = User.objects.create_user("dev_user", "dev@user.com", "123456")

        self.application = Application(
            name="test_client_credentials_app",
            user=self.dev_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
        )
        self.application.save()

        oauth2_settings.SCOPES = ['read', 'write']

    def tearDown(self):
        self.application.delete()
        self.test_user.delete()
        self.dev_user.delete()


class TestClientCredentialTokenView(BaseTest):
    def test_client_credential(self):
        """
        Request an access token using Client Credential Flow
        """
        token_request_data = {
            'grant_type': 'client_credentials',
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)


class TestClientCredentialProtectedResource(BaseTest):
    def test_client_credential_access_allowed(self):
        token_request_data = {
            'grant_type': 'client_credentials',
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('token'), data=token_request_data, **auth_headers)
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