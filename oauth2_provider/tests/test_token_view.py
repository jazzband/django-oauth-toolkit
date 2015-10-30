from __future__ import unicode_literals

import datetime

from django.core.urlresolvers import reverse
from django.test import TestCase
from django.utils import timezone

from ..models import get_application_model, AccessToken
from ..compat import get_user_model

Application = get_application_model()
UserModel = get_user_model()


class TestAuthorizedTokenViews(TestCase):
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

    def test_list_view_authorization_required(self):
        response = self.client.get(reverse('oauth2_provider:authorized-token-list'))
        self.assertEqual(response.status_code, 302)

    def test_empty_list_view(self):
        self.client.login(username="foo_user", password="123456")

        response = self.client.get(reverse('oauth2_provider:authorized-token-list'))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'There are no authorized tokens yet.', response.content)

    def test_list_view_one_token(self):
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
        print(response.content.decode())
        self.assertNotIn(b'There are no authorized tokens yet.', response.content)

    def test_list_view_shows_correct_user_token(self):
        """
        Test that only logged-in user's token are shown
        """
        self.client.login(username="bar_user", password="123456")
        AccessToken.objects.create(user=self.foo_user, token='1234567890',
                                   application=self.application,
                                   expires=timezone.now() + datetime.timedelta(days=1),
                                   scope='read write')

        response = self.client.get(reverse('oauth2_provider:authorized-token-list'))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'There are no authorized tokens yet.', response.content)

    def test_delete_view_authorization_required(self):
        self.token = AccessToken.objects.create(user=self.foo_user, token='1234567890',
                                                application=self.application,
                                                expires=timezone.now() + datetime.timedelta(days=1),
                                                scope='read write')

        response = self.client.get(reverse('oauth2_provider:authorized-token-delete', kwargs={'pk': self.token.pk}))
        self.assertEqual(response.status_code, 302)

    def test_delete_view_works(self):
        self.token = AccessToken.objects.create(user=self.foo_user, token='1234567890',
                                                application=self.application,
                                                expires=timezone.now() + datetime.timedelta(days=1),
                                                scope='read write')

        self.client.login(username="foo_user", password="123456")
        response = self.client.get(reverse('oauth2_provider:authorized-token-delete', kwargs={'pk': self.token.pk}))
        self.assertEqual(response.status_code, 200)

    def test_delete_view_token_belongs_to_user(self):
        """
        Only show if token belongs to logged-in user!
        """
        self.token = AccessToken.objects.create(user=self.foo_user, token='1234567890',
                                                application=self.application,
                                                expires=timezone.now() + datetime.timedelta(days=1),
                                                scope='read write')

        self.client.login(username="bar_user", password="123456")
        response = self.client.get(reverse('oauth2_provider:authorized-token-delete', kwargs={'pk': self.token.pk}))
        self.assertEqual(response.status_code, 404)

    def test_delete_view_post_actually_deletes(self):
        self.token = AccessToken.objects.create(user=self.foo_user, token='1234567890',
                                                application=self.application,
                                                expires=timezone.now() + datetime.timedelta(days=1),
                                                scope='read write')

        self.client.login(username="foo_user", password="123456")
        response = self.client.post(reverse('oauth2_provider:authorized-token-delete', kwargs={'pk': self.token.pk}))
        self.assertFalse(AccessToken.objects.exists())
        self.assertRedirects(response, reverse('oauth2_provider:authorized-token-list'))
