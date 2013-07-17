import json

from django.test import TestCase, RequestFactory
from django.core.urlresolvers import reverse

from ..decorators import protected_resource, rw_protected_resource
from ..compat import get_user_model
from ..settings import oauth2_settings
from ..models import Application
from .test_utils import TestCaseUtils


@protected_resource
def view(request, *args, **kwargs):
    return 'protected contents'


@rw_protected_resource
def another_view(request, *args, **kwargs):
    return 'other protected contents'


class TestProtectedResourceDecorator(TestCase, TestCaseUtils):
    @classmethod
    def setUpClass(cls):
        cls.request_factory = RequestFactory()

    def setUp(self):
        self.user = get_user_model().objects.create_user("test_user", "test@user.com", "123456")
        self.application = Application(
            name="test_client_credentials_app",
            user=self.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
        )
        self.application.save()
        oauth2_settings._SCOPES = ['read', 'write']

    def _get_token(self, scopes=None):
        """
        Request an access token using Client Credential Flow
        """
        token_request_data = {
            'grant_type': 'client_credentials',
        }
        if scopes is not None:
            token_request_data['scope'] = scopes
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        return content['access_token']

    def test_access_denied(self):

        request = self.request_factory.get("/fake-req")
        response = view(request)
        self.assertEqual(response.status_code, 403)

    def test_access_allowed(self):
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + self._get_token(),
        }
        request = self.request_factory.get("/fake-resource", **auth_headers)
        request.user = self.user

        @protected_resource
        def view(request, *args, **kwargs):
            return 'protected contents'

        response = view(request)
        self.assertEqual(response, "protected contents")

    def test_rw_protected(self):
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + self._get_token('read'),
        }
        request = self.request_factory.post("/fake-resource", **auth_headers)
        request.user = self.user
        response = another_view(request)
        self.assertEqual(response.status_code, 403)
        #self.assertEqual(response, "other protected contents")
