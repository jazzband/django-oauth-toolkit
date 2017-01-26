from __future__ import unicode_literals

import datetime

from django.contrib.auth import get_user_model
from django.test import TestCase, RequestFactory
from django.utils import timezone

from ..compat import reverse, urlencode
from ..models import get_application_model, AccessToken, RefreshToken
from ..settings import oauth2_settings

from .test_utils import TestCaseUtils


Application = get_application_model()
UserModel = get_user_model()


class BaseTest(TestCaseUtils, TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.test_user = UserModel.objects.create_user("test_user", "test@user.com", "123456")
        self.dev_user = UserModel.objects.create_user("dev_user", "dev@user.com", "123456")

        self.application = Application(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.it",
            user=self.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        self.application.save()

        oauth2_settings._SCOPES = ['read', 'write']

    def tearDown(self):
        self.application.delete()
        self.test_user.delete()
        self.dev_user.delete()


class TestRevocationView(BaseTest):
    def test_revoke_access_token(self):
        """

        """
        tok = AccessToken.objects.create(user=self.test_user, token='1234567890',
                                         application=self.application,
                                         expires=timezone.now() + datetime.timedelta(days=1),
                                         scope='read write')
        query_string = urlencode({
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
            'token': tok.token,
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:revoke-token'), qs=query_string)
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'')
        self.assertFalse(AccessToken.objects.filter(id=tok.id).exists())

    def test_revoke_access_token_public(self):
        public_app = Application(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.it",
            user=self.dev_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        public_app.save()

        tok = AccessToken.objects.create(user=self.test_user, token='1234567890',
                                         application=public_app,
                                         expires=timezone.now() + datetime.timedelta(days=1),
                                         scope='read write')

        query_string = urlencode({
            'client_id': public_app.client_id,
            'token': tok.token,
        })

        url = "{url}?{qs}".format(url=reverse('oauth2_provider:revoke-token'), qs=query_string)
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)

    def test_revoke_access_token_with_hint(self):
        """

        """
        tok = AccessToken.objects.create(user=self.test_user, token='1234567890',
                                         application=self.application,
                                         expires=timezone.now() + datetime.timedelta(days=1),
                                         scope='read write')
        query_string = urlencode({
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
            'token': tok.token,
            'token_type_hint': 'access_token'
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:revoke-token'), qs=query_string)
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(AccessToken.objects.filter(id=tok.id).exists())

    def test_revoke_access_token_with_invalid_hint(self):
        """

        """
        tok = AccessToken.objects.create(user=self.test_user, token='1234567890',
                                         application=self.application,
                                         expires=timezone.now() + datetime.timedelta(days=1),
                                         scope='read write')
        # invalid hint should have no effect
        query_string = urlencode({
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
            'token': tok.token,
            'token_type_hint': 'bad_hint'
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:revoke-token'), qs=query_string)
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(AccessToken.objects.filter(id=tok.id).exists())

    def test_revoke_refresh_token(self):
        """

        """
        tok = AccessToken.objects.create(user=self.test_user, token='1234567890',
                                         application=self.application,
                                         expires=timezone.now() + datetime.timedelta(days=1),
                                         scope='read write')
        rtok = RefreshToken.objects.create(user=self.test_user, token='999999999',
                                           application=self.application, access_token=tok)
        query_string = urlencode({
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
            'token': rtok.token,
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:revoke-token'), qs=query_string)
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(RefreshToken.objects.filter(id=rtok.id).exists())
        self.assertFalse(AccessToken.objects.filter(id=rtok.access_token.id).exists())

    def test_revoke_token_with_wrong_hint(self):
        """
        From the revocation rfc, `Section 4.1.2`_ :

        If the server is unable to locate the token using the given hint,
        it MUST extend its search across all of its supported token types
        .. _`Section 4.1.2`: http://tools.ietf.org/html/draft-ietf-oauth-revocation-11#section-4.1.2
        """
        tok = AccessToken.objects.create(user=self.test_user, token='1234567890',
                                         application=self.application,
                                         expires=timezone.now() + datetime.timedelta(days=1),
                                         scope='read write')

        query_string = urlencode({
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
            'token': tok.token,
            'token_type_hint': 'refresh_token'
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:revoke-token'), qs=query_string)
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(AccessToken.objects.filter(id=tok.id).exists())
