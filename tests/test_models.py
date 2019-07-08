from datetime import datetime as dt

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.test import TestCase
from django.test.utils import override_settings
from django.utils import timezone

from oauth2_provider.models import (
    clear_expired, get_access_token_model, get_application_model,
    get_grant_model, get_refresh_token_model
)
from oauth2_provider.settings import oauth2_settings


Application = get_application_model()
Grant = get_grant_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()


class TestModels(TestCase):

    def setUp(self):
        self.user = UserModel.objects.create_user("test_user", "test@example.com", "123456")

    def test_allow_scopes(self):
        self.client.login(username="test_user", password="123456")
        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        access_token = AccessToken(
            user=self.user,
            scope="read write",
            expires=0,
            token="",
            application=app
        )

        self.assertTrue(access_token.allow_scopes(["read", "write"]))
        self.assertTrue(access_token.allow_scopes(["write", "read"]))
        self.assertTrue(access_token.allow_scopes(["write", "read", "read"]))
        self.assertTrue(access_token.allow_scopes([]))
        self.assertFalse(access_token.allow_scopes(["write", "destroy"]))

    def test_grant_authorization_code_redirect_uris(self):
        app = Application(
            name="test_app",
            redirect_uris="",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        self.assertRaises(ValidationError, app.full_clean)

    def test_grant_implicit_redirect_uris(self):
        app = Application(
            name="test_app",
            redirect_uris="",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_IMPLICIT,
        )

        self.assertRaises(ValidationError, app.full_clean)

    def test_str(self):
        app = Application(
            redirect_uris="",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_IMPLICIT,
        )
        self.assertEqual("%s" % app, app.client_id)

        app.name = "test_app"
        self.assertEqual("%s" % app, "test_app")

    def test_scopes_property(self):
        self.client.login(username="test_user", password="123456")

        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        access_token = AccessToken(
            user=self.user,
            scope="read write",
            expires=0,
            token="",
            application=app
        )

        access_token2 = AccessToken(
            user=self.user,
            scope="write",
            expires=0,
            token="",
            application=app
        )

        self.assertEqual(access_token.scopes, {"read": "Reading scope", "write": "Writing scope"})
        self.assertEqual(access_token2.scopes, {"write": "Writing scope"})


@override_settings(
    OAUTH2_PROVIDER_APPLICATION_MODEL="tests.SampleApplication",
    OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL="tests.SampleAccessToken",
    OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL="tests.SampleRefreshToken",
    OAUTH2_PROVIDER_GRANT_MODEL="tests.SampleGrant"
)
class TestCustomModels(TestCase):

    def setUp(self):
        self.user = UserModel.objects.create_user("test_user", "test@example.com", "123456")

    def test_custom_application_model(self):
        """
        If a custom application model is installed, it should be present in
        the related objects and not the swapped out one.

        See issue #90 (https://github.com/jazzband/django-oauth-toolkit/issues/90)
        """
        related_object_names = [
            f.name for f in UserModel._meta.get_fields()
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]
        self.assertNotIn("oauth2_provider:application", related_object_names)
        self.assertIn("tests_sampleapplication", related_object_names)

    def test_custom_application_model_incorrect_format(self):
        # Patch oauth2 settings to use a custom Application model
        oauth2_settings.APPLICATION_MODEL = "IncorrectApplicationFormat"

        self.assertRaises(ValueError, get_application_model)

        # Revert oauth2 settings
        oauth2_settings.APPLICATION_MODEL = "oauth2_provider.Application"

    def test_custom_application_model_not_installed(self):
        # Patch oauth2 settings to use a custom Application model
        oauth2_settings.APPLICATION_MODEL = "tests.ApplicationNotInstalled"

        self.assertRaises(LookupError, get_application_model)

        # Revert oauth2 settings
        oauth2_settings.APPLICATION_MODEL = "oauth2_provider.Application"

    def test_custom_access_token_model(self):
        """
        If a custom access token model is installed, it should be present in
        the related objects and not the swapped out one.
        """
        # Django internals caches the related objects.
        related_object_names = [
            f.name for f in UserModel._meta.get_fields()
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]
        self.assertNotIn("oauth2_provider:access_token", related_object_names)
        self.assertIn("tests_sampleaccesstoken", related_object_names)

    def test_custom_access_token_model_incorrect_format(self):
        # Patch oauth2 settings to use a custom AccessToken model
        oauth2_settings.ACCESS_TOKEN_MODEL = "IncorrectAccessTokenFormat"

        self.assertRaises(ValueError, get_access_token_model)

        # Revert oauth2 settings
        oauth2_settings.ACCESS_TOKEN_MODEL = "oauth2_provider.AccessToken"

    def test_custom_access_token_model_not_installed(self):
        # Patch oauth2 settings to use a custom AccessToken model
        oauth2_settings.ACCESS_TOKEN_MODEL = "tests.AccessTokenNotInstalled"

        self.assertRaises(LookupError, get_access_token_model)

        # Revert oauth2 settings
        oauth2_settings.ACCESS_TOKEN_MODEL = "oauth2_provider.AccessToken"

    def test_custom_refresh_token_model(self):
        """
        If a custom refresh token model is installed, it should be present in
        the related objects and not the swapped out one.
        """
        # Django internals caches the related objects.
        related_object_names = [
            f.name for f in UserModel._meta.get_fields()
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]
        self.assertNotIn("oauth2_provider:refresh_token", related_object_names)
        self.assertIn("tests_samplerefreshtoken", related_object_names)

    def test_custom_refresh_token_model_incorrect_format(self):
        # Patch oauth2 settings to use a custom RefreshToken model
        oauth2_settings.REFRESH_TOKEN_MODEL = "IncorrectRefreshTokenFormat"

        self.assertRaises(ValueError, get_refresh_token_model)

        # Revert oauth2 settings
        oauth2_settings.REFRESH_TOKEN_MODEL = "oauth2_provider.RefreshToken"

    def test_custom_refresh_token_model_not_installed(self):
        # Patch oauth2 settings to use a custom AccessToken model
        oauth2_settings.REFRESH_TOKEN_MODEL = "tests.RefreshTokenNotInstalled"

        self.assertRaises(LookupError, get_refresh_token_model)

        # Revert oauth2 settings
        oauth2_settings.REFRESH_TOKEN_MODEL = "oauth2_provider.RefreshToken"

    def test_custom_grant_model(self):
        """
        If a custom grant model is installed, it should be present in
        the related objects and not the swapped out one.
        """
        # Django internals caches the related objects.
        related_object_names = [
            f.name for f in UserModel._meta.get_fields()
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]
        self.assertNotIn("oauth2_provider:grant", related_object_names)
        self.assertIn("tests_samplegrant", related_object_names)

    def test_custom_grant_model_incorrect_format(self):
        # Patch oauth2 settings to use a custom Grant model
        oauth2_settings.GRANT_MODEL = "IncorrectGrantFormat"

        self.assertRaises(ValueError, get_grant_model)

        # Revert oauth2 settings
        oauth2_settings.GRANT_MODEL = "oauth2_provider.Grant"

    def test_custom_grant_model_not_installed(self):
        # Patch oauth2 settings to use a custom AccessToken model
        oauth2_settings.GRANT_MODEL = "tests.GrantNotInstalled"

        self.assertRaises(LookupError, get_grant_model)

        # Revert oauth2 settings
        oauth2_settings.GRANT_MODEL = "oauth2_provider.Grant"


class TestGrantModel(TestCase):

    def test_str(self):
        grant = Grant(code="test_code")
        self.assertEqual("%s" % grant, grant.code)

    def test_expires_can_be_none(self):
        grant = Grant(code="test_code")
        self.assertIsNone(grant.expires)
        self.assertTrue(grant.is_expired())


class TestAccessTokenModel(TestCase):

    def setUp(self):
        self.user = UserModel.objects.create_user("test_user", "test@example.com", "123456")

    def test_str(self):
        access_token = AccessToken(token="test_token")
        self.assertEqual("%s" % access_token, access_token.token)

    def test_user_can_be_none(self):
        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        access_token = AccessToken.objects.create(token="test_token", application=app, expires=timezone.now())
        self.assertIsNone(access_token.user)

    def test_expires_can_be_none(self):
        access_token = AccessToken(token="test_token")
        self.assertIsNone(access_token.expires)
        self.assertTrue(access_token.is_expired())


class TestRefreshTokenModel(TestCase):

    def test_str(self):
        refresh_token = RefreshToken(token="test_token")
        self.assertEqual("%s" % refresh_token, refresh_token.token)


class TestClearExpired(TestCase):

    def setUp(self):
        self.user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        # Insert two tokens on database.
        AccessToken.objects.create(
            id=1,
            token="555",
            expires=dt.now(),
            scope=2,
            application_id=3,
            user_id=1,
            created=dt.now(),
            updated=dt.now(),
            source_refresh_token_id="0",
            )
        AccessToken.objects.create(
            id=2,
            token="666",
            expires=dt.now(),
            scope=2,
            application_id=3,
            user_id=1,
            created=dt.now(),
            updated=dt.now(),
            source_refresh_token_id="1",
            )

    def test_clear_expired_tokens(self):
        oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = 60
        assert clear_expired() is None

    def test_clear_expired_tokens_incorect_timetype(self):
        oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = "A"
        with pytest.raises(ImproperlyConfigured) as excinfo:
            clear_expired()
        result = excinfo.value.__class__.__name__
        assert result == "ImproperlyConfigured"

    def test_clear_expired_tokens_with_tokens(self):
        self.client.login(username="test_user", password="123456")
        oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = 0
        ttokens = AccessToken.objects.count()
        expiredt = AccessToken.objects.filter(expires__lte=dt.now()).count()
        assert ttokens == 2
        assert expiredt == 2
        clear_expired()
        expiredt = AccessToken.objects.filter(expires__lte=dt.now()).count()
        assert expiredt == 0
