import json
import urllib
from urlparse import urlparse, parse_qs

from django.core.urlresolvers import reverse
from django.contrib.auth import get_user_model
from django.test import TestCase, RequestFactory

from ..models import Application
from ..views import ProtectedResourceView
from ..settings import oauth2_settings


# mocking a protected resource view
class ResourceView(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


class BaseTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.test_user = get_user_model().objects.create_user("test_user", "test@user.com", "123456")

        self.code_application = Application(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.it",
            user=self.test_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        self.code_application.save()

        self.token_application = Application(
            name="test_implicit_app",
            redirect_uris="http://localhost http://example.com http://example.it",
            user=self.test_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_IMPLICIT,
        )
        self.token_application.save()

        self.password_application = Application(
            name="test_password_app",
            user=self.test_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_PASSWORD,
        )
        self.password_application.save()

        self.client_credentials_application = Application(
            name="test_client_credentials_app",
            user=self.test_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
        )
        self.client_credentials_application.save()

        oauth2_settings.SCOPES = ['read', 'write']

    def tearDown(self):
        self.code_application.delete()
        self.test_user.delete()


class TestAuthorizationCodeView(BaseTest):
    def test_code_pre_auth_invalid_client(self):
        """
        Test error for an invalid client_id with response_type: code
        """
        self.client.login(username="test_user", password="123456")

        query_string = urllib.urlencode({
            'client_id': 'fakeclientid',
            'response_type': 'code',
        })
        url = "{url}?{qs}".format(url=reverse('authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)

    def test_token_pre_auth_invalid_client(self):
        """
        Test error for an invalid client_id with response_type: token
        """
        self.client.login(username="test_user", password="123456")

        query_string = urllib.urlencode({
            'client_id': 'fakeclientid',
            'response_type': 'token',
        })
        url = "{url}?{qs}".format(url=reverse('authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)

    def test_code_pre_auth_valid_client(self):
        """
        Test response for a valid client_id with response_type: code
        """
        self.client.login(username="test_user", password="123456")

        query_string = urllib.urlencode({
            'client_id': self.code_application.client_id,
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
        self.assertEqual(form['scopes'].value(), "read write")
        self.assertEqual(form['client_id'].value(), self.code_application.client_id)

    def test_implicit_pre_auth_valid_client(self):
        """
        Test response for a valid client_id with response_type: token
        """
        self.client.login(username="test_user", password="123456")

        query_string = urllib.urlencode({
            'client_id': self.token_application.client_id,
            'response_type': 'token',
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
        self.assertEqual(form['scopes'].value(), "read write")
        self.assertEqual(form['client_id'].value(), self.token_application.client_id)

    def test_code_pre_auth_default_redirect(self):
        """
        Test for default redirect uri if omitted from query string with response_type: code
        """
        self.client.login(username="test_user", password="123456")

        query_string = urllib.urlencode({
            'client_id': self.code_application.client_id,
            'response_type': 'code',
        })
        url = "{url}?{qs}".format(url=reverse('authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        form = response.context.get("form")
        self.assertEqual(form['redirect_uri'].value(), "http://localhost")

    def test_token_pre_auth_default_redirect(self):
        """
        Test for default redirect uri if omitted from query string with response_type: token
        """
        self.client.login(username="test_user", password="123456")

        query_string = urllib.urlencode({
            'client_id': self.token_application.client_id,
            'response_type': 'token',
        })
        url = "{url}?{qs}".format(url=reverse('authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        form = response.context.get("form")
        self.assertEqual(form['redirect_uri'].value(), "http://localhost")

    def test_code_pre_auth_forbibben_redirect(self):
        """
        Test error when passing a forbidden redirect_uri in query string with response_type: code
        """
        self.client.login(username="test_user", password="123456")

        query_string = urllib.urlencode({
            'client_id': self.code_application.client_id,
            'response_type': 'code',
            'redirect_uri': 'http://forbidden.it',
        })
        url = "{url}?{qs}".format(url=reverse('authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)

    def test_token_pre_auth_forbibben_redirect(self):
        """
        Test error when passing a forbidden redirect_uri in query string with response_type: token
        """
        self.client.login(username="test_user", password="123456")

        query_string = urllib.urlencode({
            'client_id': self.token_application.client_id,
            'response_type': 'token',
            'redirect_uri': 'http://forbidden.it',
        })
        url = "{url}?{qs}".format(url=reverse('authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)

    def test_code_post_auth_allow(self):
        """
        Test authorization code is given for an allowed request with response_type: code
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.code_application.client_id,
            'state': 'random_state_string',
            'scopes': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': True,
        }

        response = self.client.post(reverse('authorize'), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn('http://example.it/?state=random_state_string&code=', response['Location'])

    def test_token_post_auth_allow(self):
        """
        Test authorization code is given for an allowed request with response_type: token
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.token_application.client_id,
            'state': 'random_state_string',
            'scopes': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'token',
            'allow': True,
        }

        response = self.client.post(reverse('authorize'), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn('http://example.it/#access_token=', response['Location'])
        self.assertIn('&state=random_state_string', response['Location'])

    def test_code_post_auth_deny(self):
        """
        Test error when resource owner deny access
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.code_application.client_id,
            'state': 'random_state_string',
            'scopes': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': False,
        }

        response = self.client.post(reverse('authorize'), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=access_denied", response['Location'])

    def test_token_post_auth_deny(self):
        """
        Test error when resource owner deny access
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.code_application.client_id,
            'state': 'random_state_string',
            'scopes': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'token',
            'allow': False,
        }

        response = self.client.post(reverse('authorize'), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=access_denied", response['Location'])


class TestTokenView(BaseTest):
    def get_auth(self):
        """
        Helper method to retrieve a valid authorization code
        """
        authcode_data = {
            'client_id': self.code_application.client_id,
            'state': 'random_state_string',
            'scopes': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': True,
        }

        response = self.client.post(reverse('authorize'), data=authcode_data)
        query_dict = parse_qs(urlparse(response['Location']).query)
        return query_dict['code'].pop()

    def test_token_request_basic_auth(self):
        """
        Request an access token using basic authentication for client authentication
        """
        self.client.login(username="test_user", password="123456")
        authorization_code = self.get_auth()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it'
        }
        user_pass = '{0}:{1}'.format(self.code_application.client_id, self.code_application.client_secret)
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Basic ' + user_pass.encode('base64'),
        }

        response = self.client.post(reverse('token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content)
        self.assertEqual(content['token_type'], "Bearer")
        self.assertEqual(content['scope'], "read write")
        self.assertEqual(content['expires_in'], 36000)

    def test_resource_owner_password(self):
        """
        Request an access token using Resource Owner Password Flow
        """
        token_request_data = {
            'grant_type': 'password',
            'client_id': self.password_application.client_id,
            'client_secret': self.password_application.client_secret,
            'username': 'test_user',
            'password': '123456',
        }

        response = self.client.post(reverse('token'), data=token_request_data)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content)
        self.assertEqual(content['token_type'], "Bearer")
        self.assertEqual(content['scope'], "read write")
        self.assertEqual(content['expires_in'], 36000)

    def test_client_credential(self):
        """
        Request an access token using Client Credential Flow
        """
        token_request_data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_credentials_application.client_id,
            'client_secret': self.client_credentials_application.client_secret,
        }

        response = self.client.post(reverse('token'), data=token_request_data)
        self.assertEqual(response.status_code, 200)


class TestProtectedResourceMixin(BaseTest):
    def test_code_resource_access_allowed(self):
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.code_application.client_id,
            'state': 'random_state_string',
            'scopes': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': True,
        }
        response = self.client.post(reverse('authorize'), data=authcode_data)
        query_dict = parse_qs(urlparse(response['Location']).query)
        authorization_code = query_dict['code'].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it'
        }
        user_pass = '{0}:{1}'.format(self.code_application.client_id, self.code_application.client_secret)
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Basic ' + user_pass.encode('base64'),
        }
        response = self.client.post(reverse('token'), data=token_request_data, **auth_headers)
        content = json.loads(response.content)
        access_token = content['access_token']

        # use token to access the resource
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")

    def test_token_resource_access_allowed(self):
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.token_application.client_id,
            'state': 'random_state_string',
            'scopes': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'token',
            'allow': True,
        }
        response = self.client.post(reverse('authorize'), data=authcode_data)
        # within implicit grant, access token is in the url fragment
        frag_dict = parse_qs(urlparse(response['Location']).fragment)
        access_token = frag_dict['access_token'].pop()

        # use token to access the resource
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")

    def test_password_resource_access_allowed(self):
        token_request_data = {
            'grant_type': 'password',
            'client_id': self.password_application.client_id,
            'client_secret': self.password_application.client_secret,
            'username': 'test_user',
            'password': '123456',
        }

        response = self.client.post(reverse('token'), data=token_request_data)
        content = json.loads(response.content)
        access_token = content['access_token']

        # use token to access the resource
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")

    def test_client_credential_access_allowed(self):
        token_request_data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_credentials_application.client_id,
            'client_secret': self.client_credentials_application.client_secret,
        }

        response = self.client.post(reverse('token'), data=token_request_data)
        content = json.loads(response.content)
        access_token = content['access_token']

        # use token to access the resource
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")

    def test_resource_access_deny(self):
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + "faketoken",
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 403)
