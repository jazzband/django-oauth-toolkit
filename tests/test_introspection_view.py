import calendar
import datetime

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.settings import oauth2_settings


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()


class TestTokenIntrospectionViews(TestCase):
    """
    Tests for Authorized Token Introspection Views
    """
    def setUp(self):
        self.resource_server_user = UserModel.objects.create_user("resource_server", "test@example.com")
        self.test_user = UserModel.objects.create_user("bar_user", "dev@example.com")

        self.application = Application(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.test_user,
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

        self.valid_token = AccessToken.objects.create(
            user=self.test_user, token="12345678901",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write dolphin"
        )

        self.invalid_token = AccessToken.objects.create(
            user=self.test_user, token="12345678902",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=-1),
            scope="read write dolphin"
        )

        self.token_without_user = AccessToken.objects.create(
            user=None, token="12345678903",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write dolphin"
        )

        self.token_without_app = AccessToken.objects.create(
            user=self.test_user, token="12345678904",
            application=None,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write dolphin"
        )

        oauth2_settings._SCOPES = ["read", "write", "introspection", "dolphin"]
        oauth2_settings.READ_SCOPE = "read"
        oauth2_settings.WRITE_SCOPE = "write"

    def tearDown(self):
        oauth2_settings._SCOPES = ["read", "write"]
        AccessToken.objects.all().delete()
        Application.objects.all().delete()
        UserModel.objects.all().delete()

    def test_view_forbidden(self):
        """
        Test that the view is restricted for logged-in users.
        """
        response = self.client.get(reverse("oauth2_provider:introspect"))
        self.assertEqual(response.status_code, 403)

    def test_view_get_valid_token(self):
        """
        Test that when you pass a valid token as URL parameter,
        a json with an active token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"),
            {"token": self.valid_token.token},
            **auth_headers)

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(content, {
            "active": True,
            "scope": self.valid_token.scope,
            "client_id": self.valid_token.application.client_id,
            "username": self.valid_token.user.get_username(),
            "exp": int(calendar.timegm(self.valid_token.expires.timetuple())),
        })

    def test_view_get_valid_token_without_user(self):
        """
        Test that when you pass a valid token as URL parameter,
        a json with an active token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"),
            {"token": self.token_without_user.token},
            **auth_headers)

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(content, {
            "active": True,
            "scope": self.token_without_user.scope,
            "client_id": self.token_without_user.application.client_id,
            "exp": int(calendar.timegm(self.token_without_user.expires.timetuple())),
        })

    def test_view_get_valid_token_without_app(self):
        """
        Test that when you pass a valid token as URL parameter,
        a json with an active token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"),
            {"token": self.token_without_app.token},
            **auth_headers)

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(content, {
            "active": True,
            "scope": self.token_without_app.scope,
            "username": self.token_without_app.user.get_username(),
            "exp": int(calendar.timegm(self.token_without_app.expires.timetuple())),
        })

    def test_view_get_invalid_token(self):
        """
        Test that when you pass an invalid token as URL parameter,
        a json with an inactive token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"),
            {"token": self.invalid_token.token},
            **auth_headers)

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(content, {
            "active": False,
        })

    def test_view_get_notexisting_token(self):
        """
        Test that when you pass an non existing token as URL parameter,
        a json with an inactive token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"),
            {"token": "kaudawelsch"},
            **auth_headers)

        self.assertEqual(response.status_code, 401)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(content, {
            "active": False,
        })

    def test_view_post_valid_token(self):
        """
        Test that when you pass a valid token as form parameter,
        a json with an active token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.post(
            reverse("oauth2_provider:introspect"),
            {"token": self.valid_token.token},
            **auth_headers)

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(content, {
            "active": True,
            "scope": self.valid_token.scope,
            "client_id": self.valid_token.application.client_id,
            "username": self.valid_token.user.get_username(),
            "exp": int(calendar.timegm(self.valid_token.expires.timetuple())),
        })

    def test_view_post_invalid_token(self):
        """
        Test that when you pass an invalid token as form parameter,
        a json with an inactive token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.post(
            reverse("oauth2_provider:introspect"),
            {"token": self.invalid_token.token},
            **auth_headers)

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(content, {
            "active": False,
        })

    def test_view_post_notexisting_token(self):
        """
        Test that when you pass an non existing token as form parameter,
        a json with an inactive token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.post(
            reverse("oauth2_provider:introspect"),
            {"token": "kaudawelsch"},
            **auth_headers)

        self.assertEqual(response.status_code, 401)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(content, {
            "active": False,
        })
