import json
import mock

from django.test import TestCase, RequestFactory
from django.test.utils import override_settings

from ..backends import get_oauthlib_core
from ..oauth2_backends import OAuthLibCore, JSONOAuthLibCore


class TestOAuthLibCoreBackend(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.oauthlib_core = OAuthLibCore()

    def test_swappable_serer_class(self):
        with mock.patch('oauth2_provider.oauth2_backends.oauth2_settings.OAUTH2_SERVER_CLASS'):
            oauthlib_core = OAuthLibCore()
            self.assertTrue(isinstance(oauthlib_core.server, mock.MagicMock))

    def test_form_urlencoded_extract_params(self):
        payload = "grant_type=password&username=john&password=123456"
        request = self.factory.post("/o/token/", payload, content_type="application/x-www-form-urlencoded")

        uri, http_method, body, headers = self.oauthlib_core._extract_params(request)
        self.assertIn("grant_type=password", body)
        self.assertIn("username=john", body)
        self.assertIn("password=123456", body)

    def test_application_json_extract_params(self):
        payload = json.dumps({
            "grant_type": "password",
            "username": "john",
            "password": "123456",
        })
        request = self.factory.post("/o/token/", payload, content_type="application/json")

        uri, http_method, body, headers = self.oauthlib_core._extract_params(request)
        self.assertNotIn("grant_type=password", body)
        self.assertNotIn("username=john", body)
        self.assertNotIn("password=123456", body)


class TestCustomOAuthLibCoreBackend(TestCase):
    """
    Tests that the public API behaves as expected when we override
    the OAuthLibCoreBackend core methods.
    """
    class MyOAuthLibCore(OAuthLibCore):
        def _get_extra_credentials(self, request):
            return 1

    def setUp(self):
        self.factory = RequestFactory()

    def test_create_token_response_gets_extra_credentials(self):
        """
        Make sures that extra_credentials parameter is passed to oauthlib
        """
        payload = "grant_type=password&username=john&password=123456"
        request = self.factory.post("/o/token/", payload, content_type="application/x-www-form-urlencoded")

        with mock.patch('oauthlib.oauth2.Server.create_token_response') as create_token_response:
            mocked = mock.MagicMock()
            create_token_response.return_value = mocked, mocked, mocked
            core = self.MyOAuthLibCore()
            core.create_token_response(request)
            self.assertTrue(create_token_response.call_args[0][4] == 1)


class TestJSONOAuthLibCoreBackend(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.oauthlib_core = JSONOAuthLibCore()

    def test_application_json_extract_params(self):
        payload = json.dumps({
            "grant_type": "password",
            "username": "john",
            "password": "123456",
        })
        request = self.factory.post("/o/token/", payload, content_type="application/json")

        uri, http_method, body, headers = self.oauthlib_core._extract_params(request)
        self.assertIn("grant_type=password", body)
        self.assertIn("username=john", body)
        self.assertIn("password=123456", body)


class TestOAuthLibCore(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_validate_authorization_request_unsafe_query(self):
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + "a_casual_token",
        }
        request = self.factory.get("/fake-resource?next=/fake", **auth_headers)

        oauthlib_core = get_oauthlib_core()
        oauthlib_core.verify_request(request, scopes=[])
