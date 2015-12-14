from __future__ import unicode_literals

try:
    from unittest import skipIf
except ImportError:
    from django.utils.unittest.case import skipIf

import django
from django.test import TestCase
from django.test.utils import override_settings
from django.core.exceptions import ValidationError
from django.utils import timezone

from ..models import get_application_model, Grant, AccessToken, RefreshToken
from ..compat import get_user_model


Application = get_application_model()
UserModel = get_user_model()


class TestModels(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create_user("test_user", "test@user.com", "123456")

    def test_allow_scopes(self):
        self.client.login(username="test_user", password="123456")
        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.it",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        access_token = AccessToken(
            user=self.user,
            scope='read write',
            expires=0,
            token='',
            application=app
        )

        self.assertTrue(access_token.allow_scopes(['read', 'write']))
        self.assertTrue(access_token.allow_scopes(['write', 'read']))
        self.assertTrue(access_token.allow_scopes(['write', 'read', 'read']))
        self.assertTrue(access_token.allow_scopes([]))
        self.assertFalse(access_token.allow_scopes(['write', 'destroy']))

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
            redirect_uris="http://localhost http://example.com http://example.it",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        access_token = AccessToken(
            user=self.user,
            scope='read write',
            expires=0,
            token='',
            application=app
        )

        access_token2 = AccessToken(
            user=self.user,
            scope='write',
            expires=0,
            token='',
            application=app
        )

        self.assertEqual(access_token.scopes, {'read': 'Reading scope', 'write': 'Writing scope'})
        self.assertEqual(access_token2.scopes, {'write': 'Writing scope'})


@skipIf(django.VERSION < (1, 5), "Behavior is broken on 1.4 and there is no solution")
@override_settings(OAUTH2_PROVIDER_APPLICATION_MODEL='tests.TestApplication')
class TestCustomApplicationModel(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create_user("test_user", "test@user.com", "123456")

    def test_related_objects(self):
        """
        If a custom application model is installed, it should be present in
        the related objects and not the swapped out one.

        See issue #90 (https://github.com/evonove/django-oauth-toolkit/issues/90)
        """
        # Django internals caches the related objects.
        if django.VERSION < (1, 8):
            del UserModel._meta._related_objects_cache
        related_object_names = [ro.name for ro in UserModel._meta.get_all_related_objects()]
        self.assertNotIn('oauth2_provider:application', related_object_names)
        self.assertIn('tests%stestapplication' % (':' if django.VERSION < (1, 8) else '_'),
                      related_object_names)


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
        self.user = UserModel.objects.create_user("test_user", "test@user.com", "123456")

    def test_str(self):
        access_token = AccessToken(token="test_token")
        self.assertEqual("%s" % access_token, access_token.token)

    def test_user_can_be_none(self):
        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.it",
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
