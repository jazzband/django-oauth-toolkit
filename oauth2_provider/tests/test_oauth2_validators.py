from django.test import TestCase

import mock
from oauthlib.common import Request

from ..oauth2_validators import OAuth2Validator
from ..models import get_application_model
from ..compat import get_user_model

UserModel = get_user_model()
AppModel = get_application_model()


class TestOAuth2Validator(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create_user("user", "test@user.com", "123456")
        self.request = mock.MagicMock(wraps=Request)
        self.request.client = None
        self.validator = OAuth2Validator()
        self.application = AppModel.objects.create(
            client_id='client_id', client_secret='client_secret', user=self.user,
            client_type=AppModel.CLIENT_PUBLIC, authorization_grant_type=AppModel.GRANT_PASSWORD)

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
