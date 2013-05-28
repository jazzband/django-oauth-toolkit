import json
import urllib
from urlparse import urlparse, parse_qs

from django.core.urlresolvers import reverse
from django.contrib.auth import get_user_model
from django.views.generic import View
from django.test import TestCase, RequestFactory

from ..models import Application
from ..views import ProtectedResourceMixin


class BaseTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.test_user = get_user_model().objects.create_user("test_user", "test@user.com", "123456")

        self.application = Application(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.it",
            user=self.test_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        self.application.save()

    def tearDown(self):
        self.application.delete()
        self.test_user.delete()


class TestAuthorizationCodeView(BaseTest):
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

        form_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scopes': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': True,
        }

        response = self.client.post(reverse('authorize'), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn('http://example.it/?state=random_state_string&code=', response['Location'])

    def test_post_auth_deny(self):
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scopes': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': False,
        }

        response = self.client.post(reverse('authorize'), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=access_denied", response['Location'])


class TestTokenView(BaseTest):
    def test_token_request(self):
        self.client.login(username="test_user", password="123456")

        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scopes': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': True,
        }

        response = self.client.post(reverse('authorize'), data=authcode_data)
        query_dict = parse_qs(urlparse(response['Location']).query)
        authorization_code = query_dict['code'].pop()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it'
        }
        user_pass = '{0}:{1}'.format(self.application.client_id, self.application.client_secret)
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Basic ' + user_pass.encode('base64'),
        }

        response = self.client.post(reverse('token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content)
        self.assertEqual(content['token_type'], "Bearer")
        self.assertEqual(content['scope'], "read write")
        self.assertEqual(content['expires_in'], 36000)


class TestProtectedResourceMixin(BaseTest):
    def test_resource_access_allowed(self):
        self.client.login(username="test_user", password="123456")

        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scopes': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': True,
        }
        response = self.client.post(reverse('authorize'), data=authcode_data)
        query_dict = parse_qs(urlparse(response['Location']).query)
        authorization_code = query_dict['code'].pop()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it'
        }
        user_pass = '{0}:{1}'.format(self.application.client_id, self.application.client_secret)
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Basic ' + user_pass.encode('base64'),
        }
        response = self.client.post(reverse('token'), data=token_request_data, **auth_headers)
        content = json.loads(response.content)
        access_token = content['access_token']

        class ResourceView(ProtectedResourceMixin, View):
            def get(self, request, *args, **kwargs):
                return "This is a protected resource"

        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")

    def test_resource_access_deny(self):
        class ResourceView(ProtectedResourceMixin, View):
            def get(self, request, *args, **kwargs):
                return "This is a protected resource"

        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + "faketoken",
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 403)
