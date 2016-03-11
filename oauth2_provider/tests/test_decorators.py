from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, RequestFactory
from django.utils import timezone

from ..decorators import protected_resource, rw_protected_resource
from ..settings import oauth2_settings
from ..models import get_application_model, AccessToken
from .test_utils import TestCaseUtils


Application = get_application_model()
UserModel = get_user_model()


class TestProtectedResourceDecorator(TestCase, TestCaseUtils):
    @classmethod
    def setUpClass(cls):
        cls.request_factory = RequestFactory()
        super(TestProtectedResourceDecorator, cls).setUpClass()

    def setUp(self):
        self.user = UserModel.objects.create_user("test_user", "test@user.com", "123456")
        self.application = Application.objects.create(
            name="test_client_credentials_app",
            user=self.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
        )

        self.access_token = AccessToken.objects.create(
            user=self.user,
            scope='read write',
            expires=timezone.now() + timedelta(seconds=300),
            token='secret-access-token-key',
            application=self.application
        )

        oauth2_settings._SCOPES = ['read', 'write']

    def test_access_denied(self):
        @protected_resource()
        def view(request, *args, **kwargs):
            return 'protected contents'

        request = self.request_factory.get("/fake-resource")
        response = view(request)
        self.assertEqual(response.status_code, 403)

    def test_access_allowed(self):
        @protected_resource()
        def view(request, *args, **kwargs):
            return 'protected contents'

        @protected_resource(scopes=['can_touch_this'])
        def scoped_view(request, *args, **kwargs):
            return 'moar protected contents'

        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + self.access_token.token,
        }
        request = self.request_factory.get("/fake-resource", **auth_headers)
        response = view(request)
        self.assertEqual(response, "protected contents")

        # now with scopes
        self.access_token.scope = 'can_touch_this'
        self.access_token.save()
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + self.access_token.token,
        }
        request = self.request_factory.get("/fake-resource", **auth_headers)
        response = scoped_view(request)
        self.assertEqual(response, "moar protected contents")

    def test_rw_protected(self):
        self.access_token.scope = 'exotic_scope write'
        self.access_token.save()
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + self.access_token.token,
        }

        @rw_protected_resource(scopes=['exotic_scope'])
        def scoped_view(request, *args, **kwargs):
            return 'other protected contents'

        request = self.request_factory.post("/fake-resource", **auth_headers)
        response = scoped_view(request)
        self.assertEqual(response, "other protected contents")

        request = self.request_factory.get("/fake-resource", **auth_headers)
        response = scoped_view(request)
        self.assertEqual(response.status_code, 403)
