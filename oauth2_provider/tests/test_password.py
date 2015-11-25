from __future__ import unicode_literals

import json

from django.test import TestCase, RequestFactory
from django.core.urlresolvers import reverse

from ..models import get_application_model
from ..settings import oauth2_settings
from ..views import ProtectedResourceView
from ..compat import get_user_model
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
            name="Test Password Application",
            user=self.dev_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_PASSWORD,
        )
        self.application.save()

        oauth2_settings._SCOPES = ['read', 'write']
        oauth2_settings._DEFAULT_SCOPES = ['read', 'write']

    def tearDown(self):
        self.application.delete()
        self.test_user.delete()
        self.dev_user.delete()


class TestPasswordTokenView(BaseTest):
    def test_get_token(self):
        """
        Request an access token using Resource Owner Password Flow
        """
        token_request_data = {
            'grant_type': 'password',
            'username': 'test_user',
            'password': '123456',
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content['token_type'], "Bearer")
        self.assertEqual(content['scope'], "read write")
        self.assertEqual(content['expires_in'], oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    def test_bad_credentials(self):
        """
        Request an access token using Resource Owner Password Flow
        """
        token_request_data = {
            'grant_type': 'password',
            'username': 'test_user',
            'password': 'NOT_MY_PASS',
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 401)


class TestPasswordProtectedResource(BaseTest):
    def test_password_resource_access_allowed(self):
        token_request_data = {
            'grant_type': 'password',
            'username': 'test_user',
            'password': '123456',
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
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
