from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.test import TestCase
from django.test.utils import override_settings
from django.utils import timezone

from oauth2_provider.models import (
    clear_expired,
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_id_token_model,
    get_refresh_token_model,
)

from . import presets


Application = get_application_model()
Grant = get_grant_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()
IDToken = get_id_token_model()


class BaseTestModels(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create_user("test_user", "test@example.com", "123456")

    def tearDown(self):
        self.user.delete()


class TestModels(BaseTestModels):
    def test_allow_scopes(self):
        self.client.login(username="test_user", password="123456")
        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        access_token = AccessToken(user=self.user, scope="read write", expires=0, token="", application=app)

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

        access_token = AccessToken(user=self.user, scope="read write", expires=0, token="", application=app)

        access_token2 = AccessToken(user=self.user, scope="write", expires=0, token="", application=app)

        self.assertEqual(access_token.scopes, {"read": "Reading scope", "write": "Writing scope"})
        self.assertEqual(access_token2.scopes, {"write": "Writing scope"})


@override_settings(
    OAUTH2_PROVIDER_APPLICATION_MODEL="tests.SampleApplication",
    OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL="tests.SampleAccessToken",
    OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL="tests.SampleRefreshToken",
    OAUTH2_PROVIDER_GRANT_MODEL="tests.SampleGrant",
)
@pytest.mark.usefixtures("oauth2_settings")
class TestCustomModels(BaseTestModels):
    def test_custom_application_model(self):
        """
        If a custom application model is installed, it should be present in
        the related objects and not the swapped out one.

        See issue #90 (https://github.com/jazzband/django-oauth-toolkit/issues/90)
        """
        related_object_names = [
            f.name
            for f in UserModel._meta.get_fields()
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]
        self.assertNotIn("oauth2_provider:application", related_object_names)
        self.assertIn("tests_sampleapplication", related_object_names)

    def test_custom_application_model_incorrect_format(self):
        # Patch oauth2 settings to use a custom Application model
        self.oauth2_settings.APPLICATION_MODEL = "IncorrectApplicationFormat"

        self.assertRaises(ValueError, get_application_model)

    def test_custom_application_model_not_installed(self):
        # Patch oauth2 settings to use a custom Application model
        self.oauth2_settings.APPLICATION_MODEL = "tests.ApplicationNotInstalled"

        self.assertRaises(LookupError, get_application_model)

    def test_custom_access_token_model(self):
        """
        If a custom access token model is installed, it should be present in
        the related objects and not the swapped out one.
        """
        # Django internals caches the related objects.
        related_object_names = [
            f.name
            for f in UserModel._meta.get_fields()
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]
        self.assertNotIn("oauth2_provider:access_token", related_object_names)
        self.assertIn("tests_sampleaccesstoken", related_object_names)

    def test_custom_access_token_model_incorrect_format(self):
        # Patch oauth2 settings to use a custom AccessToken model
        self.oauth2_settings.ACCESS_TOKEN_MODEL = "IncorrectAccessTokenFormat"

        self.assertRaises(ValueError, get_access_token_model)

    def test_custom_access_token_model_not_installed(self):
        # Patch oauth2 settings to use a custom AccessToken model
        self.oauth2_settings.ACCESS_TOKEN_MODEL = "tests.AccessTokenNotInstalled"

        self.assertRaises(LookupError, get_access_token_model)

    def test_custom_refresh_token_model(self):
        """
        If a custom refresh token model is installed, it should be present in
        the related objects and not the swapped out one.
        """
        # Django internals caches the related objects.
        related_object_names = [
            f.name
            for f in UserModel._meta.get_fields()
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]
        self.assertNotIn("oauth2_provider:refresh_token", related_object_names)
        self.assertIn("tests_samplerefreshtoken", related_object_names)

    def test_custom_refresh_token_model_incorrect_format(self):
        # Patch oauth2 settings to use a custom RefreshToken model
        self.oauth2_settings.REFRESH_TOKEN_MODEL = "IncorrectRefreshTokenFormat"

        self.assertRaises(ValueError, get_refresh_token_model)

    def test_custom_refresh_token_model_not_installed(self):
        # Patch oauth2 settings to use a custom AccessToken model
        self.oauth2_settings.REFRESH_TOKEN_MODEL = "tests.RefreshTokenNotInstalled"

        self.assertRaises(LookupError, get_refresh_token_model)

    def test_custom_grant_model(self):
        """
        If a custom grant model is installed, it should be present in
        the related objects and not the swapped out one.
        """
        # Django internals caches the related objects.
        related_object_names = [
            f.name
            for f in UserModel._meta.get_fields()
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]
        self.assertNotIn("oauth2_provider:grant", related_object_names)
        self.assertIn("tests_samplegrant", related_object_names)

    def test_custom_grant_model_incorrect_format(self):
        # Patch oauth2 settings to use a custom Grant model
        self.oauth2_settings.GRANT_MODEL = "IncorrectGrantFormat"

        self.assertRaises(ValueError, get_grant_model)

    def test_custom_grant_model_not_installed(self):
        # Patch oauth2 settings to use a custom AccessToken model
        self.oauth2_settings.GRANT_MODEL = "tests.GrantNotInstalled"

        self.assertRaises(LookupError, get_grant_model)


class TestGrantModel(BaseTestModels):
    def setUp(self):
        super().setUp()
        self.application = Application.objects.create(
            name="Test Application",
            redirect_uris="",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

    def tearDown(self):
        self.application.delete()
        super().tearDown()

    def test_str(self):
        grant = Grant(code="test_code")
        self.assertEqual("%s" % grant, grant.code)

    def test_expires_can_be_none(self):
        grant = Grant(code="test_code")
        self.assertIsNone(grant.expires)
        self.assertTrue(grant.is_expired())

    def test_redirect_uri_can_be_longer_than_255_chars(self):
        long_redirect_uri = "http://example.com/{}".format("authorized/" * 25)
        self.assertTrue(len(long_redirect_uri) > 255)
        grant = Grant.objects.create(
            user=self.user,
            code="test_code",
            application=self.application,
            expires=timezone.now(),
            redirect_uri=long_redirect_uri,
            scope="",
        )
        grant.refresh_from_db()

        # It would be necessary to run test using another DB engine than sqlite
        # that transform varchar(255) into text data type.
        # https://sqlite.org/datatype3.html#affinity_name_examples
        self.assertEqual(grant.redirect_uri, long_redirect_uri)


class TestAccessTokenModel(BaseTestModels):
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


class TestRefreshTokenModel(BaseTestModels):
    def test_str(self):
        refresh_token = RefreshToken(token="test_token")
        self.assertEqual("%s" % refresh_token, refresh_token.token)


@pytest.mark.usefixtures("oauth2_settings")
class TestClearExpired(BaseTestModels):
    def setUp(self):
        super().setUp()
        # Insert many tokens, both expired and not, and grants.
        self.num_tokens = 100
        now = timezone.now()
        earlier = now - timedelta(seconds=100)
        later = now + timedelta(seconds=100)
        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        # make 200 access tokens, half current and half expired.
        expired_access_tokens = AccessToken.objects.bulk_create(
            AccessToken(token="expired AccessToken {}".format(i), expires=earlier)
            for i in range(self.num_tokens)
        )
        current_access_tokens = AccessToken.objects.bulk_create(
            AccessToken(token=f"current AccessToken {i}", expires=later) for i in range(self.num_tokens)
        )
        # Give the first half of the access tokens a refresh token,
        # alternating between current and expired ones.
        RefreshToken.objects.bulk_create(
            RefreshToken(
                token=f"expired AT's refresh token {i}",
                application=app,
                access_token=expired_access_tokens[i].pk,
                user=self.user,
            )
            for i in range(0, len(expired_access_tokens) // 2, 2)
        )
        RefreshToken.objects.bulk_create(
            RefreshToken(
                token=f"current AT's refresh token {i}",
                application=app,
                access_token=current_access_tokens[i].pk,
                user=self.user,
            )
            for i in range(1, len(current_access_tokens) // 2, 2)
        )
        # Make some grants, half of which are expired.
        Grant.objects.bulk_create(
            Grant(
                user=self.user,
                code=f"old grant code {i}",
                application=app,
                expires=earlier,
                redirect_uri="https://localhost/redirect",
            )
            for i in range(self.num_tokens)
        )
        Grant.objects.bulk_create(
            Grant(
                user=self.user,
                code=f"new grant code {i}",
                application=app,
                expires=later,
                redirect_uri="https://localhost/redirect",
            )
            for i in range(self.num_tokens)
        )

    def test_clear_expired_tokens(self):
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = 60
        assert clear_expired() is None

    def test_clear_expired_tokens_incorect_timetype(self):
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = "A"
        with pytest.raises(ImproperlyConfigured) as excinfo:
            clear_expired()
        result = excinfo.value.__class__.__name__
        assert result == "ImproperlyConfigured"

    def test_clear_expired_tokens_with_tokens(self):
        self.oauth2_settings.CLEAR_EXPIRED_TOKENS_BATCH_SIZE = 10
        self.oauth2_settings.CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL = 0.0
        at_count = AccessToken.objects.count()
        assert at_count == 2 * self.num_tokens, f"{2 * self.num_tokens} access tokens should exist."
        rt_count = RefreshToken.objects.count()
        assert rt_count == self.num_tokens // 2, f"{self.num_tokens // 2} refresh tokens should exist."
        gt_count = Grant.objects.count()
        assert gt_count == self.num_tokens * 2, f"{self.num_tokens * 2} grants should exist."
        clear_expired()
        at_count = AccessToken.objects.count()
        assert at_count == self.num_tokens, "Half the access tokens should not have been deleted."
        rt_count = RefreshToken.objects.count()
        assert rt_count == self.num_tokens // 2, "Half of the refresh tokens should have been deleted."
        gt_count = Grant.objects.count()
        assert gt_count == self.num_tokens, "Half the grants should have been deleted."


@pytest.mark.django_db
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_id_token_methods(oidc_tokens, rf):
    id_token = IDToken.objects.get()

    # Token was just created, so should be valid
    assert id_token.is_valid()

    # if expires is None, it should always be expired
    # the column is NOT NULL, but could be NULL in sub-classes
    id_token.expires = None
    assert id_token.is_expired()

    # if no scopes are passed, they should be valid
    assert id_token.allow_scopes(None)

    # if the requested scopes are in the token, they should be valid
    assert id_token.allow_scopes(["openid"])

    # if the requested scopes are not in the token, they should not be valid
    assert id_token.allow_scopes(["fizzbuzz"]) is False

    # we should be able to get a list of the scopes on the token
    assert id_token.scopes == {"openid": "OpenID connect"}

    # the id token should stringify as the JWT token
    id_token_str = str(id_token)
    assert str(id_token.jti) in id_token_str
    assert id_token_str.endswith(str(id_token.user_id))

    # revoking the token should delete it
    id_token.revoke()
    assert IDToken.objects.filter(jti=id_token.jti).count() == 0


@pytest.mark.django_db
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_key(oauth2_settings, application):
    # RS256 key
    key = application.jwk_key
    assert key.key_type == "RSA"

    # RS256 key, but not configured
    oauth2_settings.OIDC_RSA_PRIVATE_KEY = None
    with pytest.raises(ImproperlyConfigured) as exc:
        application.jwk_key
    assert "You must set OIDC_RSA_PRIVATE_KEY" in str(exc.value)

    # HS256 key
    application.algorithm = Application.HS256_ALGORITHM
    key = application.jwk_key
    assert key.key_type == "oct"

    # No algorithm
    application.algorithm = Application.NO_ALGORITHM
    with pytest.raises(ImproperlyConfigured) as exc:
        application.jwk_key
    assert "This application does not support signed tokens" == str(exc.value)


@pytest.mark.django_db
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean(oauth2_settings, application):
    # RS256, RSA key is configured
    application.clean()

    # RS256, RSA key is not configured
    oauth2_settings.OIDC_RSA_PRIVATE_KEY = None
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert "You must set OIDC_RSA_PRIVATE_KEY" in str(exc.value)

    # HS256 algorithm, auth code + confidential -> allowed
    application.algorithm = Application.HS256_ALGORITHM
    application.clean()

    # HS256, auth code + public -> forbidden
    application.client_type = Application.CLIENT_PUBLIC
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert "You cannot use HS256" in str(exc.value)

    # HS256, hybrid + confidential -> forbidden
    application.client_type = Application.CLIENT_CONFIDENTIAL
    application.authorization_grant_type = Application.GRANT_OPENID_HYBRID
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert "You cannot use HS256" in str(exc.value)
