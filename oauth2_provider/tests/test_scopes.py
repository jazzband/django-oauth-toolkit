from __future__ import unicode_literals

import json

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse
from django.test import TestCase, RequestFactory

from .test_utils import TestCaseUtils
from ..compat import urlparse, parse_qs, urlencode
from ..models import get_application_model, Grant, AccessToken
from ..settings import oauth2_settings
from ..views import ScopedProtectedResourceView, ReadWriteScopedResourceView


Application = get_application_model()
UserModel = get_user_model()


# mocking a protected resource view
class ScopeResourceView(ScopedProtectedResourceView):
    required_scopes = ['scope1']

    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


class MultiScopeResourceView(ScopedProtectedResourceView):
    required_scopes = ['scope1', 'scope2']

    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


class ReadWriteResourceView(ReadWriteScopedResourceView):
    def get(self, request, *args, **kwargs):
        return "This is a read protected resource"

    def post(self, request, *args, **kwargs):
        return "This is a write protected resource"


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

        oauth2_settings._SCOPES = ['read', 'write', 'scope1', 'scope2', 'scope3']
        oauth2_settings.READ_SCOPE = 'read'
        oauth2_settings.WRITE_SCOPE = 'write'

    def tearDown(self):
        self.application.delete()
        self.test_user.delete()
        self.dev_user.delete()


class TestScopesQueryParameterBackwardsCompatibility(BaseTest):
    def setUp(self):
        super(TestScopesQueryParameterBackwardsCompatibility, self).setUp()
        oauth2_settings._SCOPES = ['read', 'write']
        oauth2_settings._DEFAULT_SCOPES = ['read', 'write']

    def test_scopes_query_parameter_is_supported_on_post(self):
        """
        Tests support for plural `scopes` query parameter on POST requests.

        """
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scopes': 'read write',  # using plural `scopes`
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': True,
        }
        response = self.client.post(reverse('oauth2_provider:authorize'), data=authcode_data)
        query_dict = parse_qs(urlparse(response['Location']).query)
        authorization_code = query_dict['code'].pop()

        grant = Grant.objects.get(code=authorization_code)
        self.assertEqual(grant.scope, "read write")

    def test_scopes_query_parameter_is_supported_on_get(self):
        """
        Tests support for plural `scopes` query parameter on GET requests.

        """
        self.client.login(username="test_user", password="123456")

        query_string = urlencode({
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scopes': 'read write',  # using plural `scopes`
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
        })
        url = "{url}?{qs}".format(url=reverse('oauth2_provider:authorize'), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # check form is in context
        self.assertIn("form", response.context)

        form = response.context["form"]
        self.assertEqual(form['scope'].value(), "read write")


class TestScopesSave(BaseTest):
    def test_scopes_saved_in_grant(self):
        """
        Test scopes are properly saved in grant
        """
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'scope1 scope2',
            'redirect_uri': 'http://example.it',
            'response_type': 'code',
            'allow': True,
        }
        response = self.client.post(reverse('oauth2_provider:authorize'), data=authcode_data)
        query_dict = parse_qs(urlparse(response['Location']).query)
        authorization_code = query_dict['code'].pop()

        grant = Grant.objects.get(code=authorization_code)
        self.assertEqual(grant.scope, "scope1 scope2")

    def test_scopes_save_in_access_token(self):
        """
        Test scopes are properly saved in access token
        """
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'scope1 scope2',
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

        at = AccessToken.objects.get(token=access_token)
        self.assertEqual(at.scope, "scope1 scope2")


class TestScopesProtection(BaseTest):
    def test_scopes_protection_valid(self):
        """
        Test access to a scope protected resource with correct scopes provided
        """
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'scope1 scope2',
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

        view = ScopeResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")

    def test_scopes_protection_fail(self):
        """
        Test access to a scope protected resource with wrong scopes provided
        """
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'scope2',
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

        view = ScopeResourceView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 403)

    def test_multi_scope_fail(self):
        """
        Test access to a multi-scope protected resource with wrong scopes provided
        """
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'scope1 scope3',
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

        view = MultiScopeResourceView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 403)

    def test_multi_scope_valid(self):
        """
        Test access to a multi-scope protected resource with correct scopes provided
        """
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': 'scope1 scope2',
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

        view = MultiScopeResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")


class TestReadWriteScope(BaseTest):
    def get_access_token(self, scopes):
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            'client_id': self.application.client_id,
            'state': 'random_state_string',
            'scope': scopes,
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
        return content['access_token']

    def test_improperly_configured(self):
        oauth2_settings._SCOPES = ['scope1']

        request = self.factory.get("/fake")
        view = ReadWriteResourceView.as_view()
        self.assertRaises(ImproperlyConfigured, view, request)

        oauth2_settings._SCOPES = ['read', 'write']
        oauth2_settings.READ_SCOPE = 'ciccia'

        view = ReadWriteResourceView.as_view()
        self.assertRaises(ImproperlyConfigured, view, request)

    def test_properly_configured(self):
        oauth2_settings._SCOPES = ['scope1']

        request = self.factory.get("/fake")
        view = ReadWriteResourceView.as_view()
        self.assertRaises(ImproperlyConfigured, view, request)

        oauth2_settings._SCOPES = ['read', 'write']
        oauth2_settings.READ_SCOPE = 'ciccia'

        view = ReadWriteResourceView.as_view()
        self.assertRaises(ImproperlyConfigured, view, request)

    def test_has_read_scope(self):
        access_token = self.get_access_token('read')

        # use token to access the resource
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ReadWriteResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a read protected resource")

    def test_no_read_scope(self):
        access_token = self.get_access_token('scope1')

        # use token to access the resource
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ReadWriteResourceView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 403)

    def test_has_write_scope(self):
        access_token = self.get_access_token('write')

        # use token to access the resource
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        request = self.factory.post("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ReadWriteResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a write protected resource")

    def test_no_write_scope(self):
        access_token = self.get_access_token('scope1')

        # use token to access the resource
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        request = self.factory.post("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ReadWriteResourceView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 403)
