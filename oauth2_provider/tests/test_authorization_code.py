from __future__ import unicode_literals

import base64
import json
import datetime
import mock

from django.contrib.auth import get_user_model
from django.core.urlresolvers import reverse
from django.test import TestCase, RequestFactory
from django.utils import timezone

from ..compat import urlparse, parse_qs, urlencode
from ..models import get_application_model, Grant, AccessToken, RefreshToken
from ..settings import oauth2_settings
from ..views import ProtectedResourceView

from .test_utils import TestCaseUtils


Application = get_application_model()
UserModel = get_user_model()


# mocking a protected resource view
class ResourceView(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


class BaseTest(TestCaseUtils, TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.test_user = UserModel.objects.create_user("test_user", "test@user.com", "123456")
        self.dev_user = UserModel.objects.create_user("dev_user", "dev@user.com", "123456")

        oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES = ['http', 'custom-scheme']

        self.application = Application(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.it custom-scheme://example.com",
            user=self.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        self.application.save()

        oauth2_settings._SCOPES = ['read', 'write']
        oauth2_settings._DEFAULT_SCOPES = ['read', 'write']

    def tearDown(self):
        self.application.delete()
        self.test_user.delete()
        self.dev_user.delete()


class TestAuthorizationCodeView(BaseTest):
    def test_skip_authorization_completely(self):
        """
        If application.skip_authorization = True, should skip the authorization page.
        """
        self.client.login(username="test_user", password="123456")
        self.application.skip_authorization = True
        self.application.save()

        query_string = urlencode({
            'client_id': self.application.client_id,
            'response_type': 'code',
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.it',
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)

    def test_pre_auth_invalid_client(self):
        """
        Test error for an invalid client_id with response_type: code
        """
        self.client.login(username="test_user", password="123456")

        query_string = urlencode({
            'client_id': 'fakeclientid',
            'response_type': 'code',
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)

    def test_pre_auth_valid_client(self):
        """
        Test response for a valid client_id with response_type: code
        """
        self.client.login(username="test_user", password="123456")

        query_string = urlencode({
            'client_id': self.application.client_id,
            'response_type': 'code',
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.it',
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # check form is in context and form params are valid
        self.assertIn("form", response.context)

        form = response.context["form"]
        self.assertEqual(form['redirect_uri'].value(), "http://example.it")
        self.assertEqual(form['state'].value(), "random_state_string")
        self.assertEqual(form['scope'].value(), "read write")
        self.assertEqual(form['client_id'].value(), self.application.client_id)

    def test_pre_auth_valid_client_custom_redirect_uri_scheme(self):
        """
        Test response for a valid client_id with response_type: code
        using a non-standard, but allowed, redirect_uri scheme.
        """
        self.client.login(username="test_user", password="123456")

        query_string = urlencode({
            'client_id': self.application.client_id,
            'response_type': 'code',
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'custom-scheme://example.com',
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # check form is in context and form params are valid
        self.assertIn("form", response.context)

        form = response.context["form"]
        self.assertEqual(form['redirect_uri'].value(), "custom-scheme://example.com")
        self.assertEqual(form['state'].value(), "random_state_string")
        self.assertEqual(form['scope'].value(), "read write")
        self.assertEqual(form['client_id'].value(), self.application.client_id)

    def test_pre_auth_approval_prompt(self):
        """
        TODO
        """
        tok = AccessToken.objects.create(user=self.test_user, token='1234567890',
                                         application=self.application,
                                         expires=timezone.now() + datetime.timedelta(days=1),
                                         scope='read write')
        self.client.login(username="test_user", password="123456")
        query_string = urlencode({
            'client_id': self.application.client_id,
            'response_type': 'code',
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.it',
            'approval_prompt': 'auto',
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:authorize'), qs=query_string)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        # user already authorized the application, but with different scopes: prompt them.
        tok.scope = 'read'
        tok.save()
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_pre_auth_approval_prompt_default(self):
        """
        TODO
        """
        self.assertEqual(oauth2_settings.REQUEST_APPROVAL_PROMPT, 'force')

        AccessToken.objects.create(user=self.test_user, token='1234567890',
                                   application=self.application,
                                   expires=timezone.now() + datetime.timedelta(days=1),
                                   scope='read write')
        self.client.login(username="test_user", password="123456")
        query_string = urlencode({
            'client_id': self.application.client_id,
            'response_type': 'code',
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.it',
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:authorize'), qs=query_string)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_pre_auth_approval_prompt_default_override(self):
        """
        TODO
        """
        oauth2_settings.REQUEST_APPROVAL_PROMPT = 'auto'

        AccessToken.objects.create(user=self.test_user, token='1234567890',
                                   application=self.application,
                                   expires=timezone.now() + datetime.timedelta(days=1),
                                   scope='read write')
        self.client.login(username="test_user", password="123456")
        query_string = urlencode({
            'client_id': self.application.client_id,
            'response_type': 'code',
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.it',
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:authorize'), qs=query_string)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)

    def test_pre_auth_default_redirect(self):
        """
        Test for default redirect uri if omitted from query string with response_type: code
        """
        self.client.login(username="test_user", password="123456")

        query_string = urlencode({
            'client_id': self.application.client_id,
            'response_type': 'code',
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        form = response.context["form"]
        self.assertEqual(form['redirect_uri'].value(), "http://localhost")

    def test_pre_auth_forbibben_redirect(self):
        """
        Test error when passing a forbidden redirect_uri in query string with response_type: code
        """
        self.client.login(username="test_user", password="123456")

        query_string = urlencode({
            'client_id': self.application.client_id,
            'response_type': 'code',
            'redirect_uri': 'http://forbidden.it',
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)

    def test_pre_auth_wrong_response_type(self):
        """
        Test error when passing a wrong response_type in query string
        """
        self.client.login(username="test_user", password="123456")

        query_string = urlencode({
            'client_id': self.application.client_id,
            'response_type': 'WRONG',
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=unsupported_response_type", response['Location'])

    def test_code_post_auth_allow(self):
        """
        Test authorization code is given for an allowed request with response_type: code
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': True,
        }

        response = self.client.post(reverse('oauth2_provider:authorize'), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn('http://example.it?', response['Location'])
        self.assertIn('state=random_state_string', response['Location'])
        self.assertIn('code=', response['Location'])

    def test_code_post_auth_deny(self):
        """
        Test error when resource owner deny access
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': False,
        }

        response = self.client.post(reverse('oauth2_provider:authorize'), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=access_denied", response['Location'])

    def test_code_post_auth_bad_responsetype(self):
        """
        Test authorization code is given for an allowed request with a response_type not supported
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'UNKNOWN',
            'allow': True,
        }

        response = self.client.post(reverse('oauth2_provider:authorize'), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn('http://example.it?error', response['Location'])

    def test_code_post_auth_forbidden_redirect_uri(self):
        """
        Test authorization code is given for an allowed request with a forbidden redirect_uri
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://forbidden.it',
            'response_type': 'code',
            'allow': True,
        }

        response = self.client.post(reverse('oauth2_provider:authorize'), data=form_data)
        self.assertEqual(response.status_code, 400)

    def test_code_post_auth_malicious_redirect_uri(self):
        """
        Test validation of a malicious redirect_uri
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': '/../',
            'response_type': 'code',
            'allow': True,
        }

        response = self.client.post(reverse('oauth2_provider:authorize'), data=form_data)
        self.assertEqual(response.status_code, 400)

    def test_code_post_auth_allow_custom_redirect_uri_scheme(self):
        """
        Test authorization code is given for an allowed request with response_type: code
        using a non-standard, but allowed, redirect_uri scheme.
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'custom-scheme://example.com',
            'response_type': 'code',
            'allow': True,
        }

        response = self.client.post(reverse('oauth2_provider:authorize'), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn('custom-scheme://example.com?', response['Location'])
        self.assertIn('state=random_state_string', response['Location'])
        self.assertIn('code=', response['Location'])

    def test_code_post_auth_deny_custom_redirect_uri_scheme(self):
        """
        Test error when resource owner deny access
        using a non-standard, but allowed, redirect_uri scheme.
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'custom-scheme://example.com',
            'response_type': 'code',
            'allow': False,
        }

        response = self.client.post(reverse('oauth2_provider:authorize'), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn('custom-scheme://example.com?', response['Location'])
        self.assertIn("error=access_denied", response['Location'])

    def test_code_post_auth_redirection_uri_with_querystring(self):
        """
        Tests that a redirection uri with query string is allowed
        and query string is retained on redirection.
        See http://tools.ietf.org/html/rfc6749#section-3.1.2
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.com?foo=bar',
            'response_type': 'code',
            'allow': True,
        }

        response = self.client.post(reverse('oauth2_provider:authorize'), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.com?foo=bar", response['Location'])
        self.assertIn("code=", response['Location'])

    def test_code_post_auth_failing_redirection_uri_with_querystring(self):
        """
        Test that in case of error the querystring of the redirection uri is preserved

        See https://github.com/evonove/django-oauth-toolkit/issues/238
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.com?foo=bar',
            'response_type': 'code',
            'allow': False,
        }

        response = self.client.post(reverse('oauth2_provider:authorize'), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertEqual("http://example.com?foo=bar&error=access_denied", response['Location'])

    def test_code_post_auth_fails_when_redirect_uri_path_is_invalid(self):
        """
        Tests that a redirection uri is matched using scheme + netloc + path
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.com/a?foo=bar',
            'response_type': 'code',
            'allow': True,
        }

        response = self.client.post(reverse('oauth2_provider:authorize'), data=form_data)
        self.assertEqual(response.status_code, 400)


class TestAuthorizationCodeTokenView(BaseTest):
    def get_auth(self):
        """
        Helper method to retrieve a valid authorization code
        """
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': True,
        }

        response = self.client.post(reverse('oauth2_provider:authorize'), data=authcode_data)
        query_dict = parse_qs(urlparse(response['Location']).query)
        return query_dict['code'].pop()

    def test_basic_auth(self):
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
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content['token_type'], "Bearer")
        self.assertEqual(content['scope'], "read write")
        self.assertEqual(content['expires_in'], oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    def test_refresh(self):
        """
        Request an access token using a refresh token
        """
        self.client.login(username="test_user", password="123456")
        authorization_code = self.get_auth()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
        self.assertTrue('refresh_token' in content)

        # make a second token request to be sure the previous refresh token remains valid, see #65
        authorization_code = self.get_auth()
        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it'
        }
        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)

        token_request_data = {
            'grant_type': 'refresh_token',
            'refresh_token': content['refresh_token'],
            'scope': content['scope'],
        }
        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertTrue('access_token' in content)

        # check refresh token cannot be used twice
        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 401)
        content = json.loads(response.content.decode("utf-8"))
        self.assertTrue('invalid_grant' in content.values())

    def test_refresh_invalidates_old_tokens(self):
        """
        Ensure existing refresh tokens are cleaned up when issuing new ones
        """
        self.client.login(username="test_user", password="123456")
        authorization_code = self.get_auth()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))

        rt = content['refresh_token']
        at = content['access_token']

        token_request_data = {
            'grant_type': 'refresh_token',
            'refresh_token': rt,
            'scope': content['scope'],
        }
        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        self.assertFalse(RefreshToken.objects.filter(token=rt).exists())
        self.assertFalse(AccessToken.objects.filter(token=at).exists())

    def test_refresh_no_scopes(self):
        """
        Request an access token using a refresh token without passing any scope
        """
        self.client.login(username="test_user", password="123456")
        authorization_code = self.get_auth()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
        self.assertTrue('refresh_token' in content)

        token_request_data = {
            'grant_type': 'refresh_token',
            'refresh_token': content['refresh_token'],
        }
        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertTrue('access_token' in content)

    def test_refresh_bad_scopes(self):
        """
        Request an access token using a refresh token and wrong scopes
        """
        self.client.login(username="test_user", password="123456")
        authorization_code = self.get_auth()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
        self.assertTrue('refresh_token' in content)

        token_request_data = {
            'grant_type': 'refresh_token',
            'refresh_token': content['refresh_token'],
            'scope': 'read write nuke',
        }
        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 401)

    def test_refresh_fail_repeating_requests(self):
        """
        Try refreshing an access token with the same refresh token more than once
        """
        self.client.login(username="test_user", password="123456")
        authorization_code = self.get_auth()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
        self.assertTrue('refresh_token' in content)

        token_request_data = {
            'grant_type': 'refresh_token',
            'refresh_token': content['refresh_token'],
            'scope': content['scope'],
        }
        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)
        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 401)

    def test_refresh_repeating_requests_non_rotating_tokens(self):
        """
        Try refreshing an access token with the same refresh token more than once when not rotating tokens.
        """
        self.client.login(username="test_user", password="123456")
        authorization_code = self.get_auth()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
        self.assertTrue('refresh_token' in content)

        token_request_data = {
            'grant_type': 'refresh_token',
            'refresh_token': content['refresh_token'],
            'scope': content['scope'],
        }

        with mock.patch('oauthlib.oauth2.rfc6749.request_validator.RequestValidator.rotate_refresh_token',
                        return_value=False):
            response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
            self.assertEqual(response.status_code, 200)
            response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
            self.assertEqual(response.status_code, 200)

    def test_basic_auth_bad_authcode(self):
        """
        Request an access token using a bad authorization code
        """
        self.client.login(username="test_user", password="123456")

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': 'BLAH',
            'redirect_uri': 'http://example.it'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 401)

    def test_basic_auth_bad_granttype(self):
        """
        Request an access token using a bad grant_type string
        """
        self.client.login(username="test_user", password="123456")

        token_request_data = {
            'grant_type': 'UNKNOWN',
            'code': 'BLAH',
            'redirect_uri': 'http://example.it'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 400)

    def test_basic_auth_grant_expired(self):
        """
        Request an access token using an expired grant token
        """
        self.client.login(username="test_user", password="123456")
        g = Grant(application=self.application, user=self.test_user, code='BLAH', expires=timezone.now(),
                  redirect_uri='', scope='')
        g.save()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': 'BLAH',
            'redirect_uri': 'http://example.it'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 401)

    def test_basic_auth_bad_secret(self):
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
        auth_headers = self.get_basic_auth_header(self.application.client_id, 'BOOM!')

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 401)

    def test_basic_auth_wrong_auth_type(self):
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

        user_pass = '{0}:{1}'.format(self.application.client_id, self.application.client_secret)
        auth_string = base64.b64encode(user_pass.encode('utf-8'))
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Wrong ' + auth_string.decode("utf-8"),
        }

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 401)

    def test_request_body_params(self):
        """
        Request an access token using client_type: public
        """
        self.client.login(username="test_user", password="123456")
        authorization_code = self.get_auth()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it',
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
        }

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content['token_type'], "Bearer")
        self.assertEqual(content['scope'], "read write")
        self.assertEqual(content['expires_in'], oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    def test_public(self):
        """
        Request an access token using client_type: public
        """
        self.client.login(username="test_user", password="123456")

        self.application.client_type = Application.CLIENT_PUBLIC
        self.application.save()
        authorization_code = self.get_auth()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it',
            'client_id': self.application.client_id
        }

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content['token_type'], "Bearer")
        self.assertEqual(content['scope'], "read write")
        self.assertEqual(content['expires_in'], oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    def test_malicious_redirect_uri(self):
        """
        Request an access token using client_type: public and ensure redirect_uri is
        properly validated.
        """
        self.client.login(username="test_user", password="123456")

        self.application.client_type = Application.CLIENT_PUBLIC
        self.application.save()
        authorization_code = self.get_auth()

        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': '/../',
            'client_id': self.application.client_id
        }

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data)
        self.assertEqual(response.status_code, 401)

    def test_code_exchange_succeed_when_redirect_uri_match(self):
        """
        Tests code exchange succeed when redirect uri matches the one used for code request
        """
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.it?foo=bar',
            'response_type': 'code',
            'allow': True,
        }
        response = self.client.post(reverse('oauth2_provider:authorize'), data=authcode_data)
        query_dict = parse_qs(urlparse(response['Location']).query)
        authorization_code = query_dict['code'].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it?foo=bar'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content['token_type'], "Bearer")
        self.assertEqual(content['scope'], "read write")
        self.assertEqual(content['expires_in'], oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    def test_code_exchange_fails_when_redirect_uri_does_not_match(self):
        """
        Tests code exchange fails when redirect uri does not match the one used for code request
        """
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.it?foo=bar',
            'response_type': 'code',
            'allow': True,
        }
        response = self.client.post(reverse('oauth2_provider:authorize'), data=authcode_data)
        query_dict = parse_qs(urlparse(response['Location']).query)
        authorization_code = query_dict['code'].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it?foo=baraa'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 401)

    def test_code_exchange_succeed_when_redirect_uri_match_with_multiple_query_params(self):
        """
        Tests code exchange succeed when redirect uri matches the one used for code request
        """
        self.client.login(username="test_user", password="123456")
        self.application.redirect_uris = "http://localhost http://example.com?foo=bar"
        self.application.save()

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.com?bar=baz&foo=bar',
            'response_type': 'code',
            'allow': True,
        }
        response = self.client.post(reverse('oauth2_provider:authorize'), data=authcode_data)
        query_dict = parse_qs(urlparse(response['Location']).query)
        authorization_code = query_dict['code'].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.com?bar=baz&foo=bar'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content['token_type'], "Bearer")
        self.assertEqual(content['scope'], "read write")
        self.assertEqual(content['expires_in'], oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)


class TestAuthorizationCodeProtectedResource(BaseTest):
    def test_resource_access_allowed(self):
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'read write',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': True,
        }
        response = self.client.post(reverse('oauth2_provider:authorize'), data=authcode_data)
        query_dict = parse_qs(urlparse(response['Location']).query)
        authorization_code = query_dict['code'].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://example.it'
        }
        auth_headers = self.get_basic_auth_header(self.application.client_id, self.application.client_secret)

        response = self.client.post(reverse('oauth2_provider:token'), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
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


class TestDefaultScopes(BaseTest):

    def test_pre_auth_default_scopes(self):
        """
        Test response for a valid client_id with response_type: code using default scopes
        """
        self.client.login(username="test_user", password="123456")
        oauth2_settings._DEFAULT_SCOPES = ['read']

        query_string = urlencode({
            'client_id': self.application.client_id,
            'response_type': 'code',
            'state': 'random_state_string',
            'redirect_uri': 'http://example.it',
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # check form is in context and form params are valid
        self.assertIn("form", response.context)

        form = response.context["form"]
        self.assertEqual(form['redirect_uri'].value(), "http://example.it")
        self.assertEqual(form['state'].value(), "random_state_string")
        self.assertEqual(form['scope'].value(), 'read')
        self.assertEqual(form['client_id'].value(), self.application.client_id)
