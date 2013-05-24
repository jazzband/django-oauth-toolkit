import urllib

from django.core.urlresolvers import reverse
from django.contrib.auth import get_user_model
from django.test import TestCase

from ..models import Application


class TestAuthorizationCodeView(TestCase):
    def setUp(self):
        self.test_user = get_user_model().objects.create_user("test_user", "test@user.com", "123456")

        self.application = Application(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.it",
            user=self.test_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        self.application.save()

    def tearDown(self):
        self.application.delete()
        self.test_user.delete()

    def test_pre_auth_invalid_client(self):
        """
        Test error for an invalid
        """
        self.client.login(username="test_user", password="123456")

        query_string = urllib.urlencode({
            'client_id': 'fakeclientid',
            'response_type': 'code',
        })
        url = "{url}?{qs}".format(url=reverse('authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)

    def test_pre_auth_valid_client(self):
        """
        Test response for a valid client_id
        """
        self.client.login(username="test_user", password="123456")

        query_string = urllib.urlencode({
            'client_id': self.application.client_id,
            'response_type': 'code',
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.it',
        })
        url = "{url}?{qs}".format(url=reverse('authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # check form is in context and form params are valid
        self.assertIn("form", response.context)

        form = response.context.get("form")
        self.assertEqual(form['redirect_uri'].value(), "http://example.it")
        self.assertEqual(form['state'].value(), "random_state_string")
        self.assertEqual(form['scopes'].value(), ["read", "write"])
        self.assertEqual(form['client_id'].value(), self.application.client_id)

    def test_pre_auth_default_redirect(self):
        """
        Test for default redirect uri if omitted from query string
        """
        self.client.login(username="test_user", password="123456")

        query_string = urllib.urlencode({
            'client_id': self.application.client_id,
            'response_type': 'code',
        })
        url = "{url}?{qs}".format(url=reverse('authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        form = response.context.get("form")
        self.assertEqual(form['redirect_uri'].value(), "http://localhost")

    def test_pre_auth_forbibben_redirect(self):
        """
        Test error when passing a forbidden redirect_uri in query string
        """
        self.client.login(username="test_user", password="123456")

        query_string = urllib.urlencode({
            'client_id': self.application.client_id,
            'response_type': 'code',
            'redirect_uri': 'http://forbidden.it',
        })
        url = "{url}?{qs}".format(url=reverse('authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)

    def test_post_auth_allow(self):
        self.client.login(username="test_user", password="123456")

        # TODO: post the form and check for correct redirect with authorization code in query string

    def test_post_auth_deny(self):
        self.client.login(username="test_user", password="123456")

        # TODO: post the form and check for correct redirect with errors in query string
