from datetime import timedelta

from django.test import TestCase, Client, override_settings
from django.utils import timezone
from django.conf.urls import patterns, url
from django.http import HttpResponse
from django.views.generic import View

from ..models import AccessToken, get_application_model
from django.contrib.auth import get_user_model


Application = get_application_model()
UserModel = get_user_model()


class MockView(View):
    def post(self, request):
        return HttpResponse()

urlpatterns = patterns(
    '',
    url(r'^cors-test/$', MockView.as_view()),
)


@override_settings(
    ROOT_URLCONF='oauth2_provider.tests.test_cors_middleware',
    AUTHENTICATION_BACKENDS=('oauth2_provider.backends.OAuth2Backend',),
    MIDDLEWARE_CLASSES=(
        'oauth2_provider.middleware.OAuth2TokenMiddleware',
        'oauth2_provider.middleware.CorsMiddleware',
    ))
class TestCORSMiddleware(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create_user('test_user', 'test@user.com')
        self.application = Application.objects.create(
            name='Test Application',
            redirect_uris='https://foo.bar',
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        self.access_token = AccessToken.objects.create(
            user=self.user,
            scope='read write',
            expires=timezone.now() + timedelta(seconds=300),
            token='secret-access-token-key',
            application=self.application
        )

        auth_header = "Bearer {0}".format(self.access_token.token)
        self.client = Client(HTTP_AUTHORIZATION=auth_header)

    def test_cors_successful(self):
        '''Ensure that we get cors-headers according to our oauth-app'''
        resp = self.client.post('/cors-test/', HTTP_ORIGIN='https://foo.bar')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['Access-Control-Allow-Origin'], 'https://foo.bar')
        self.assertEqual(resp['Access-Control-Allow-Credentials'], 'true')

    def test_cors_no_auth(self):
        '''Ensure that CORS-headers are sent non-authenticated requests'''
        client = Client()
        resp = client.post('/cors-test/', HTTP_ORIGIN='https://foo.bar')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['Access-Control-Allow-Origin'], 'https://foo.bar')
        self.assertEqual(resp['Access-Control-Allow-Credentials'], 'true')

    def test_cors_wrong_origin(self):
        '''Ensure that CORS-headers aren't sent to requests from wrong origin'''
        resp = self.client.post('/cors-test/', HTTP_ORIGIN='https://bar.foo')
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.has_header('Access-Control-Allow-Origin'))

    def test_cors_200_preflight(self):
        '''Ensure that preflight always get 200 responses'''
        resp = self.client.options('/cors-test/',
                                   HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET',
                                   HTTP_ORIGIN='https://foo.bar')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['Access-Control-Allow-Origin'], 'https://foo.bar')
        self.assertTrue(resp.has_header('Access-Control-Allow-Headers'))
        self.assertTrue(resp.has_header('Access-Control-Allow-Methods'))
