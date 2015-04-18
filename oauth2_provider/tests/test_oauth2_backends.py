from django.test import TestCase, RequestFactory
from django.test.utils import override_settings

from ..backends import get_oauthlib_core


@override_settings(OAUTH2_BACKEND_CLASS='oauth2_provider.oauth2_backends.OAuthLibCore')
class TestOAuthLibCoreBackend(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.oauthlib_core = get_oauthlib_core()

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
