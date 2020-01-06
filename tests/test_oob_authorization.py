import base64
import datetime
import hashlib
import json
import re
from urllib.parse import parse_qs, urlencode, urlparse

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from oauthlib.oauth2.rfc6749 import errors as oauthlib_errors

from oauth2_provider.models import (
    get_access_token_model, get_application_model,
    get_grant_model, get_refresh_token_model
)
from oauth2_provider.settings import oauth2_settings

from .utils import get_basic_auth_header

Application = get_application_model()
AccessToken = get_access_token_model()
Grant = get_grant_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()

class BaseTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        self.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")

        oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES = ["http", "custom-scheme", "urn"]

        self.application = Application.objects.create(
            name="Test Application",
            redirect_uris="urn:ietf:wg:oauth:2.0:oob urn:ietf:wg:oauth:2.0:oob:auto",
            user=self.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        oauth2_settings._SCOPES = ["read", "write"]
        oauth2_settings._DEFAULT_SCOPES = ["read", "write"]

    def tearDown(self):
        self.application.delete()
        self.test_user.delete()
        self.dev_user.delete()

class TestOobAuthorizationCodeView(BaseTest):
    def test_oob_as_html(self):
        """
        ...
        """
        self.client.login(username="test_user", password="123456")
        self.application.skip_authorization = True
        self.application.save()

        query_string = urlencode({
            "client_id": self.application.client_id,
            "response_type": "code",
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
        })
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        content = str(response.content, encoding='UTF-8')

        code_matches = re.search(r'<code>([^<]*)</code>', content)
        code = code_matches.groups(0)
        self.assertNotEqual(code, '')

    def test_oob_as_json(self):
        """
        ...
        """
        self.client.login(username="test_user", password="123456")
        self.application.skip_authorization = True
        self.application.save()

        query_string = urlencode({
            "client_id": self.application.client_id,
            "response_type": "code",
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob:auto",
        })
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        content = json.loads(str(response.content, encoding='UTF-8'))

        for field in [
                'access_token', 'token_uri',
                'refresh_token', 'token_expiry',
                'token_uri', 'user_agent',
                'client_id', 'client_secret',
                'revoke_uri',
                ]:
            self.assertIn(field, content)
