from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TransactionTestCase
from django.utils import timezone

import mock
from oauthlib.common import Request

from ..exceptions import FatalClientError
from ..oauth2_validators import OAuth2Validator
from ..models import get_application_model, AccessToken, RefreshToken

UserModel = get_user_model()
AppModel = get_application_model()


class TestOAuth2Validator(TransactionTestCase):
    def setUp(self):
        self.user = UserModel.objects.create_user("user", "test@user.com", "123456")
        self.request = mock.MagicMock(wraps=Request)
        self.request.user = self.user
        self.request.grant_type = "not client"
        self.validator = OAuth2Validator()
        self.application = AppModel.objects.create(
            client_id='client_id', client_secret='client_secret', user=self.user,
            client_type=AppModel.CLIENT_PUBLIC, authorization_grant_type=AppModel.GRANT_PASSWORD)
        self.request.client = self.application

    def tearDown(self):
        self.application.delete()

    def test_authenticate_request_body(self):
        self.request.client_id = 'client_id'
        self.request.client_secret = ''
        self.assertFalse(self.validator._authenticate_request_body(self.request))

        self.request.client_secret = 'wrong_client_secret'
        self.assertFalse(self.validator._authenticate_request_body(self.request))

        self.request.client_secret = 'client_secret'
        self.assertTrue(self.validator._authenticate_request_body(self.request))

    def test_extract_basic_auth(self):
        self.request.headers = {'HTTP_AUTHORIZATION': 'Basic 123456'}
        self.assertEqual(self.validator._extract_basic_auth(self.request), '123456')
        self.request.headers = {}
        self.assertIsNone(self.validator._extract_basic_auth(self.request))
        self.request.headers = {'HTTP_AUTHORIZATION': 'Dummy 123456'}
        self.assertIsNone(self.validator._extract_basic_auth(self.request))
        self.request.headers = {'HTTP_AUTHORIZATION': 'Basic'}
        self.assertIsNone(self.validator._extract_basic_auth(self.request))
        self.request.headers = {'HTTP_AUTHORIZATION': 'Basic 123456 789'}
        self.assertEqual(self.validator._extract_basic_auth(self.request), '123456 789')

    def test_authenticate_basic_auth(self):
        self.request.encoding = 'utf-8'
        # client_id:client_secret
        self.request.headers = {'HTTP_AUTHORIZATION': 'Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=\n'}
        self.assertTrue(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_basic_auth_default_encoding(self):
        self.request.encoding = None
        # client_id:client_secret
        self.request.headers = {'HTTP_AUTHORIZATION': 'Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=\n'}
        self.assertTrue(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_basic_auth_wrong_client_id(self):
        self.request.encoding = 'utf-8'
        # wrong_id:client_secret
        self.request.headers = {'HTTP_AUTHORIZATION': 'Basic d3JvbmdfaWQ6Y2xpZW50X3NlY3JldA==\n'}
        self.assertFalse(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_basic_auth_wrong_client_secret(self):
        self.request.encoding = 'utf-8'
        # client_id:wrong_secret
        self.request.headers = {'HTTP_AUTHORIZATION': 'Basic Y2xpZW50X2lkOndyb25nX3NlY3JldA==\n'}
        self.assertFalse(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_basic_auth_not_b64_auth_string(self):
        self.request.encoding = 'utf-8'
        # Can't b64decode
        self.request.headers = {'HTTP_AUTHORIZATION': 'Basic not_base64'}
        self.assertFalse(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_basic_auth_not_utf8(self):
        self.request.encoding = 'utf-8'
        # b64decode('test') will become b'\xb5\xeb-', it can't be decoded as utf-8
        self.request.headers = {'HTTP_AUTHORIZATION': 'Basic test'}
        self.assertFalse(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_client_id(self):
        self.assertTrue(self.validator.authenticate_client_id('client_id', self.request))

    def test_authenticate_client_id_fail(self):
        self.application.client_type = AppModel.CLIENT_CONFIDENTIAL
        self.application.save()
        self.assertFalse(self.validator.authenticate_client_id('client_id', self.request))
        self.assertFalse(self.validator.authenticate_client_id('fake_client_id', self.request))

    def test_client_authentication_required(self):
        self.request.headers = {'HTTP_AUTHORIZATION': 'Basic 123456'}
        self.assertTrue(self.validator.client_authentication_required(self.request))
        self.request.headers = {}
        self.request.client_id = 'client_id'
        self.request.client_secret = 'client_secret'
        self.assertTrue(self.validator.client_authentication_required(self.request))
        self.request.client_secret = ''
        self.assertFalse(self.validator.client_authentication_required(self.request))
        self.application.client_type = AppModel.CLIENT_CONFIDENTIAL
        self.application.save()
        self.request.client = ''
        self.assertTrue(self.validator.client_authentication_required(self.request))

    def test_load_application_fails_when_request_has_no_client(self):
        self.assertRaises(AssertionError, self.validator.authenticate_client_id, 'client_id', {})

    def test_rotate_refresh_token__is_true(self):
        self.assertTrue(self.validator.rotate_refresh_token(mock.MagicMock()))

    def test_save_bearer_token__without_user__raises_fatal_client(self):
        token = {}

        with self.assertRaises(FatalClientError):
            self.validator.save_bearer_token(token, mock.MagicMock())

    def test_save_bearer_token__with_existing_tokens__does_not_create_new_tokens(self):

        rotate_token_function = mock.MagicMock()
        rotate_token_function.return_value = False
        self.validator.rotate_refresh_token = rotate_token_function

        access_token = AccessToken.objects.create(
            token="123",
            user=self.user,
            expires=timezone.now() + timedelta(seconds=60),
            application=self.application
        )
        refresh_token = RefreshToken.objects.create(
            access_token=access_token,
            token="abc",
            user=self.user,
            application=self.application
        )
        self.request.refresh_token_instance = refresh_token
        token = {
            "scope": "foo bar",
            "refresh_token": "abc",
            "access_token": "123",
        }

        self.assertEqual(1, RefreshToken.objects.count())
        self.assertEqual(1, AccessToken.objects.count())

        self.validator.save_bearer_token(token, self.request)

        self.assertEqual(1, RefreshToken.objects.count())
        self.assertEqual(1, AccessToken.objects.count())

    def test_save_bearer_token__checks_to_rotate_tokens(self):

        rotate_token_function = mock.MagicMock()
        rotate_token_function.return_value = False
        self.validator.rotate_refresh_token = rotate_token_function

        access_token = AccessToken.objects.create(
            token="123",
            user=self.user,
            expires=timezone.now() + timedelta(seconds=60),
            application=self.application
        )
        refresh_token = RefreshToken.objects.create(
            access_token=access_token,
            token="abc",
            user=self.user,
            application=self.application
        )
        self.request.refresh_token_instance = refresh_token
        token = {
            "scope": "foo bar",
            "refresh_token": "abc",
            "access_token": "123",
        }

        self.validator.save_bearer_token(token, self.request)
        rotate_token_function.assert_called_once_with(self.request)

    def test_save_bearer_token__with_new_token__creates_new_tokens(self):
        token = {
            "scope": "foo bar",
            "refresh_token": "abc",
            "access_token": "123",
        }

        self.assertEqual(0, RefreshToken.objects.count())
        self.assertEqual(0, AccessToken.objects.count())

        self.validator.save_bearer_token(token, self.request)

        self.assertEqual(1, RefreshToken.objects.count())
        self.assertEqual(1, AccessToken.objects.count())

    def test_save_bearer_token__with_new_token_equal_to_existing_token__revokes_old_tokens(self):
        access_token = AccessToken.objects.create(
            token="123",
            user=self.user,
            expires=timezone.now() + timedelta(seconds=60),
            application=self.application
        )
        refresh_token = RefreshToken.objects.create(
            access_token=access_token,
            token="abc",
            user=self.user,
            application=self.application
        )

        self.request.refresh_token_instance = refresh_token

        token = {
            "scope": "foo bar",
            "refresh_token": "abc",
            "access_token": "123",
        }

        self.assertEqual(1, RefreshToken.objects.count())
        self.assertEqual(1, AccessToken.objects.count())

        self.validator.save_bearer_token(token, self.request)

        self.assertEqual(1, RefreshToken.objects.count())
        self.assertEqual(1, AccessToken.objects.count())

    def test_save_bearer_token__with_no_refresh_token__creates_new_access_token_only(self):
        token = {
            "scope": "foo bar",
            "access_token": "123",
        }

        self.validator.save_bearer_token(token, self.request)

        self.assertEqual(0, RefreshToken.objects.count())
        self.assertEqual(1, AccessToken.objects.count())
