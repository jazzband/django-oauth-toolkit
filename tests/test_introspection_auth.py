import calendar
import datetime

from django.conf.urls import include, url
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.test import TestCase, override_settings
from django.utils import timezone
from oauthlib.common import Request

from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views import ScopedProtectedResourceView


try:
    from unittest import mock
except ImportError:
    import mock


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()

exp = datetime.datetime.now() + datetime.timedelta(days=1)


class ScopeResourceView(ScopedProtectedResourceView):
    required_scopes = ["dolphin"]

    def get(self, request, *args, **kwargs):
        return HttpResponse("This is a protected resource", 200)

    def post(self, request, *args, **kwargs):
        return HttpResponse("This is a protected resource", 200)


def mocked_requests_post(url, data, *args, **kwargs):
    """
    Mock the response from the authentication server
    """
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

    if "token" in data and data["token"] and data["token"] != "12345678900":
        return MockResponse({
            "active": True,
            "scope": "read write dolphin",
            "client_id": "client_id_{}".format(data["token"]),
            "username": "{}_user".format(data["token"]),
            "exp": int(calendar.timegm(exp.timetuple())),
        }, 200)

    return MockResponse({
        "active": False,
    }, 200)


urlpatterns = [
    url(r"^oauth2/", include("oauth2_provider.urls")),
    url(r"^oauth2-test-resource/$", ScopeResourceView.as_view()),
]


@override_settings(ROOT_URLCONF=__name__)
class TestTokenIntrospectionAuth(TestCase):
    """
    Tests for Authorization through token introspection
    """
    def setUp(self):
        self.validator = OAuth2Validator()
        self.request = mock.MagicMock(wraps=Request)
        self.resource_server_user = UserModel.objects.create_user(
            "resource_server", "test@example.com", "123456"
        )

        self.application = Application(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.resource_server_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        self.application.save()

        self.resource_server_token = AccessToken.objects.create(
            user=self.resource_server_user, token="12345678900",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="introspection"
        )

        self.invalid_token = AccessToken.objects.create(
            user=self.resource_server_user, token="12345678901",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=-1),
            scope="read write dolphin"
        )

        oauth2_settings._SCOPES = ["read", "write", "introspection", "dolphin"]
        oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL = "http://example.org/introspection"
        oauth2_settings.RESOURCE_SERVER_AUTH_TOKEN = self.resource_server_token.token
        oauth2_settings.READ_SCOPE = "read"
        oauth2_settings.WRITE_SCOPE = "write"

    def tearDown(self):
        oauth2_settings._SCOPES = ["read", "write"]
        oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL = None
        oauth2_settings.RESOURCE_SERVER_AUTH_TOKEN = None
        self.resource_server_token.delete()
        self.application.delete()
        AccessToken.objects.all().delete()
        UserModel.objects.all().delete()

    @mock.patch("requests.post", side_effect=mocked_requests_post)
    def test_get_token_from_authentication_server_not_existing_token(self, mock_get):
        """
        Test method _get_token_from_authentication_server with non existing token
        """
        token = self.validator._get_token_from_authentication_server(
            self.resource_server_token.token,
            oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL,
            oauth2_settings.RESOURCE_SERVER_AUTH_TOKEN,
            oauth2_settings.RESOURCE_SERVER_INTROSPECTION_CREDENTIALS
        )
        self.assertIsNone(token)

    @mock.patch("requests.post", side_effect=mocked_requests_post)
    def test_get_token_from_authentication_server_existing_token(self, mock_get):
        """
        Test method _get_token_from_authentication_server with existing token
        """
        token = self.validator._get_token_from_authentication_server(
            "foo",
            oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL,
            oauth2_settings.RESOURCE_SERVER_AUTH_TOKEN,
            oauth2_settings.RESOURCE_SERVER_INTROSPECTION_CREDENTIALS
        )
        self.assertIsInstance(token, AccessToken)
        self.assertEqual(token.user.username, "foo_user")
        self.assertEqual(token.scope, "read write dolphin")

    @mock.patch("requests.post", side_effect=mocked_requests_post)
    def test_validate_bearer_token(self, mock_get):
        """
        Test method validate_bearer_token
        """
        # with token = None
        self.assertFalse(self.validator.validate_bearer_token(None, ["dolphin"], self.request))
        # with valid token and scope
        self.assertTrue(
            self.validator.validate_bearer_token(
                self.resource_server_token.token, ["introspection"], self.request
            )
        )
        # with initially invalid token, but validated through request
        self.assertTrue(
            self.validator.validate_bearer_token(self.invalid_token.token, ["dolphin"], self.request)
        )
        # with locally unavailable token, but validated through request
        self.assertTrue(self.validator.validate_bearer_token("butzi", ["dolphin"], self.request))
        # with valid token but invalid scope
        self.assertFalse(self.validator.validate_bearer_token("foo", ["kaudawelsch"], self.request))
        # with token validated through request, but invalid scope
        self.assertFalse(self.validator.validate_bearer_token("butz", ["kaudawelsch"], self.request))
        # with token validated through request and valid scope
        self.assertTrue(self.validator.validate_bearer_token("butzi", ["dolphin"], self.request))

    @mock.patch("requests.post", side_effect=mocked_requests_post)
    def test_get_resource(self, mock_get):
        """
        Test that we can access the resource with a get request and a remotely validated token
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer bar",
        }
        response = self.client.get("/oauth2-test-resource/", **auth_headers)
        self.assertEqual(response.content.decode("utf-8"), "This is a protected resource")

    @mock.patch("requests.post", side_effect=mocked_requests_post)
    def test_post_resource(self, mock_get):
        """
        Test that we can access the resource with a post request and a remotely validated token
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer batz",
        }
        response = self.client.post("/oauth2-test-resource/", **auth_headers)
        self.assertEqual(response.content.decode("utf-8"), "This is a protected resource")
