import unittest
from datetime import timedelta

from django.conf.urls import patterns, url, include
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.test import TestCase
from django.utils import timezone

from .test_utils import TestCaseUtils
from ..models import AccessToken, get_application_model
from ..settings import oauth2_settings


Application = get_application_model()
UserModel = get_user_model()


try:
    from rest_framework import permissions
    from rest_framework.views import APIView
    from rest_framework.test import force_authenticate, APIRequestFactory
    from ..ext.rest_framework import OAuth2Authentication, TokenHasScope, TokenHasReadWriteScope, TokenHasResourceScope
    from ..ext.rest_framework import IsAuthenticatedOrTokenHasScope

    class MockView(APIView):
        permission_classes = (permissions.IsAuthenticated,)

        def get(self, request):
            return HttpResponse({'a': 1, 'b': 2, 'c': 3})

        def post(self, request):
            return HttpResponse({'a': 1, 'b': 2, 'c': 3})

    class OAuth2View(MockView):
        authentication_classes = [OAuth2Authentication]

    class ScopedView(OAuth2View):
        permission_classes = [permissions.IsAuthenticated, TokenHasScope]
        required_scopes = ['scope1']

    class AuthenticatedOrScopedView(OAuth2View):
        permission_classes = [IsAuthenticatedOrTokenHasScope]
        required_scopes = ['scope1']

    class ReadWriteScopedView(OAuth2View):
        permission_classes = [permissions.IsAuthenticated, TokenHasReadWriteScope]

    class ResourceScopedView(OAuth2View):
        permission_classes = [permissions.IsAuthenticated, TokenHasResourceScope]
        required_scopes = ['resource1']

    urlpatterns = patterns(
        '',
        url(r'^oauth2/', include('oauth2_provider.urls')),
        url(r'^oauth2-test/$', OAuth2View.as_view()),
        url(r'^oauth2-scoped-test/$', ScopedView.as_view()),
        url(r'^oauth2-read-write-test/$', ReadWriteScopedView.as_view()),
        url(r'^oauth2-resource-scoped-test/$', ResourceScopedView.as_view()),
        url(r'^oauth2-authenticated-or-scoped-test/$', AuthenticatedOrScopedView.as_view()),
    )

    rest_framework_installed = True
except ImportError:
    rest_framework_installed = False


class BaseTest(TestCaseUtils, TestCase):
    """
    TODO: add docs
    """
    pass


class TestOAuth2Authentication(BaseTest):
    urls = 'oauth2_provider.tests.test_rest_framework'

    def setUp(self):
        oauth2_settings._SCOPES = ['read', 'write', 'scope1', 'scope2', 'resource1']

        self.test_user = UserModel.objects.create_user("test_user", "test@user.com", "123456")
        self.dev_user = UserModel.objects.create_user("dev_user", "dev@user.com", "123456")

        self.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.it",
            user=self.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        self.access_token = AccessToken.objects.create(
            user=self.test_user,
            scope='read write',
            expires=timezone.now() + timedelta(seconds=300),
            token='secret-access-token-key',
            application=self.application
        )

    def _create_authorization_header(self, token):
        return "Bearer {0}".format(token)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_authentication_allow(self):
        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_authentication_denied(self):
        auth = self._create_authorization_header("fake-token")
        response = self.client.get("/oauth2-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_authentication_or_scope_denied(self):
        # user is not authenticated
        # not a correct token
        auth = self._create_authorization_header("fake-token")
        response = self.client.get("/oauth2-authenticated-or-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)
        # token doesn't have correct scope
        auth = self._create_authorization_header(self.access_token.token)

        factory = APIRequestFactory()
        request = factory.get("/oauth2-authenticated-or-scoped-test/")
        request.auth = auth
        force_authenticate(request, token=self.access_token)
        response = AuthenticatedOrScopedView.as_view()(request)
        # authenticated but wrong scope, this is 403, not 401
        self.assertEqual(response.status_code, 403)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_scoped_permission_allow(self):
        self.access_token.scope = 'scope1'
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_authenticated_or_scoped_permission_allow(self):
        self.access_token.scope = 'scope1'
        self.access_token.save()
        # correct token and correct scope
        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-authenticated-or-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

        auth = self._create_authorization_header("fake-token")
        # incorrect token  but authenticated
        factory = APIRequestFactory()
        request = factory.get("/oauth2-authenticated-or-scoped-test/")
        request.auth = auth
        force_authenticate(request, self.test_user)
        response = AuthenticatedOrScopedView.as_view()(request)
        self.assertEqual(response.status_code, 200)

        # correct token  but not authenticated
        request = factory.get("/oauth2-authenticated-or-scoped-test/")
        request.auth = auth
        self.access_token.scope = 'scope1'
        self.access_token.save()
        force_authenticate(request, token=self.access_token)
        response = AuthenticatedOrScopedView.as_view()(request)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_scoped_permission_deny(self):
        self.access_token.scope = 'scope2'
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_read_write_permission_get_allow(self):
        self.access_token.scope = 'read'
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-read-write-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_read_write_permission_post_allow(self):
        self.access_token.scope = 'write'
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.post("/oauth2-read-write-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_read_write_permission_get_deny(self):
        self.access_token.scope = 'write'
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-read-write-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_read_write_permission_post_deny(self):
        self.access_token.scope = 'read'
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.post("/oauth2-read-write-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_resource_scoped_permission_get_allow(self):
        self.access_token.scope = 'resource1:read'
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-resource-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_resource_scoped_permission_post_allow(self):
        self.access_token.scope = 'resource1:write'
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.post("/oauth2-resource-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_resource_scoped_permission_get_denied(self):
        self.access_token.scope = 'resource1:write'
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-resource-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    @unittest.skipUnless(rest_framework_installed, 'djangorestframework not installed')
    def test_resource_scoped_permission_post_denied(self):
        self.access_token.scope = 'resource1:read'
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.post("/oauth2-resource-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)
