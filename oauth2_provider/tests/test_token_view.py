from __future__ import unicode_literals

import datetime

from django.contrib.auth import get_user_model
from django.core.urlresolvers import reverse
from django.test import TestCase
from django.utils import timezone

from ..models import get_application_model, AccessToken


Application = get_application_model()
UserModel = get_user_model()


class TestAuthorizedTokenViews(TestCase):
    """
    TestCase superclass for Authorized Token Views' Test Cases
    """
    def setUp(self):
        self.foo_user = UserModel.objects.create_user("foo_user", "test@user.com", "123456")
        self.bar_user = UserModel.objects.create_user("bar_user", "dev@user.com", "123456")

        self.application = Application(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.it",
            user=self.bar_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        self.application.save()

    def tearDown(self):
        self.foo_user.delete()
        self.bar_user.delete()


class TestAuthorizedTokenListView(TestAuthorizedTokenViews):
    """
    Tests for the Authorized Token ListView
    """
    def test_list_view_authorization_required(self):
        """
        Test that the view redirects to login page if user is not logged-in.
        """
        response = self.client.get(reverse('oauth2_provider:authorized-token-list'))
        self.assertEqual(response.status_code, 302)
        self.assertTrue('/accounts/login/?next=' in response['Location'])

    def test_empty_list_view(self):
        """
        Test that when you have no tokens, an appropriate message is shown
        """
        self.client.login(username="foo_user", password="123456")

        response = self.client.get(reverse('oauth2_provider:authorized-token-list'))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'There are no authorized tokens yet.', response.content)

    def test_list_view_one_token(self):
        """
        Test that the view shows your token
        """
        self.client.login(username="bar_user", password="123456")
        AccessToken.objects.create(user=self.bar_user, token='1234567890',
                                   application=self.application,
                                   expires=timezone.now() + datetime.timedelta(days=1),
                                   scope='read write')

        response = self.client.get(reverse('oauth2_provider:authorized-token-list'))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'read', response.content)
        self.assertIn(b'write', response.content)
        self.assertNotIn(b'There are no authorized tokens yet.', response.content)

    def test_list_view_two_tokens(self):
        """
        Test that the view shows your tokens
        """
        self.client.login(username="bar_user", password="123456")
        AccessToken.objects.create(user=self.bar_user, token='1234567890',
                                   application=self.application,
                                   expires=timezone.now() + datetime.timedelta(days=1),
                                   scope='read write')
        AccessToken.objects.create(user=self.bar_user, token='0123456789',
                                   application=self.application,
                                   expires=timezone.now() + datetime.timedelta(days=1),
                                   scope='read write')

        response = self.client.get(reverse('oauth2_provider:authorized-token-list'))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'There are no authorized tokens yet.', response.content)

    def test_list_view_shows_correct_user_token(self):
        """
        Test that only currently logged-in user's tokens are shown
        """
        self.client.login(username="bar_user", password="123456")
        AccessToken.objects.create(user=self.foo_user, token='1234567890',
                                   application=self.application,
                                   expires=timezone.now() + datetime.timedelta(days=1),
                                   scope='read write')

        response = self.client.get(reverse('oauth2_provider:authorized-token-list'))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'There are no authorized tokens yet.', response.content)


class TestAuthorizedTokenDeleteView(TestAuthorizedTokenViews):
    """
    Tests for the Authorized Token DeleteView
    """
    def test_delete_view_authorization_required(self):
        """
        Test that the view redirects to login page if user is not logged-in.
        """
        self.token = AccessToken.objects.create(user=self.foo_user, token='1234567890',
                                                application=self.application,
                                                expires=timezone.now() + datetime.timedelta(days=1),
                                                scope='read write')

        response = self.client.get(reverse('oauth2_provider:authorized-token-delete', kwargs={'pk': self.token.pk}))
        self.assertEqual(response.status_code, 302)
        self.assertTrue('/accounts/login/?next=' in response['Location'])

    def test_delete_view_works(self):
        """
        Test that a GET on this view returns 200 if the token belongs to the logged-in user.
        """
        self.token = AccessToken.objects.create(user=self.foo_user, token='1234567890',
                                                application=self.application,
                                                expires=timezone.now() + datetime.timedelta(days=1),
                                                scope='read write')

        self.client.login(username="foo_user", password="123456")
        response = self.client.get(reverse('oauth2_provider:authorized-token-delete', kwargs={'pk': self.token.pk}))
        self.assertEqual(response.status_code, 200)

    def test_delete_view_token_belongs_to_user(self):
        """
        Test that a 404 is returned when trying to GET this view with someone else's tokens.
        """
        self.token = AccessToken.objects.create(user=self.foo_user, token='1234567890',
                                                application=self.application,
                                                expires=timezone.now() + datetime.timedelta(days=1),
                                                scope='read write')

        self.client.login(username="bar_user", password="123456")
        response = self.client.get(reverse('oauth2_provider:authorized-token-delete', kwargs={'pk': self.token.pk}))
        self.assertEqual(response.status_code, 404)

    def test_delete_view_post_actually_deletes(self):
        """
        Test that a POST on this view works if the token belongs to the logged-in user.
        """
        self.token = AccessToken.objects.create(user=self.foo_user, token='1234567890',
                                                application=self.application,
                                                expires=timezone.now() + datetime.timedelta(days=1),
                                                scope='read write')

        self.client.login(username="foo_user", password="123456")
        response = self.client.post(reverse('oauth2_provider:authorized-token-delete', kwargs={'pk': self.token.pk}))
        self.assertFalse(AccessToken.objects.exists())
        self.assertRedirects(response, reverse('oauth2_provider:authorized-token-list'))

    def test_delete_view_only_deletes_user_own_token(self):
        """
        Test that a 404 is returned when trying to POST on this view with someone else's tokens.
        """
        self.token = AccessToken.objects.create(user=self.foo_user, token='1234567890',
                                                application=self.application,
                                                expires=timezone.now() + datetime.timedelta(days=1),
                                                scope='read write')

        self.client.login(username="bar_user", password="123456")
        response = self.client.post(reverse('oauth2_provider:authorized-token-delete', kwargs={'pk': self.token.pk}))
        self.assertTrue(AccessToken.objects.exists())
        self.assertEqual(response.status_code, 404)
