import datetime
from unittest.mock import patch

import pytest
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.urls import reverse

from oauth2_provider.exceptions import BackchannelLogoutRequestError
from oauth2_provider.models import get_application_model, get_id_token_model, send_backchannel_logout_requests
from oauth2_provider.views import ApplicationRegistration

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
IDToken = get_id_token_model()
User = get_user_model()


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
class TestBackchannelLogout(TestCase):
    def setUp(self):
        self.developer = User.objects.create_user(username="app_developer", password="123456")
        self.user = User.objects.create_user(username="app_user", password="654321")
        self.application = Application.objects.create(
            name="test_client_credentials_app",
            user=self.developer,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            algorithm=Application.RS256_ALGORITHM,
            client_secret="1234567890asdfghjkqwertyuiopzxcvbnm",
            backchannel_logout_uri="http://rp.example.com/logout",
        )
        now = timezone.now()
        expiration_date = now + datetime.timedelta(minutes=180)
        self.id_token = IDToken.objects.create(
            application=self.application, user=self.user, expires=expiration_date
        )

    def test_on_logout_handler_is_called_for_user(self):
        with patch("oauth2_provider.models.send_backchannel_logout_requests") as backchannel_handler:
            self.client.login(username="app_user", password="654321")
            self.client.logout()
            backchannel_handler.assert_called_once()
            args, kwargs = backchannel_handler.call_args
            self.assertEqual(kwargs.get("user"), self.user)

    def test_logout_token_is_signed_for_user(self):
        with patch("requests.post") as mocked_post:
            self.client.login(username="app_user", password="654321")
            self.client.logout()
            mocked_post.assert_called_once()

    def test_raises_exception_on_bad_application(self):
        self.application.algorithm = Application.NO_ALGORITHM
        self.application.save()
        with self.assertRaises(BackchannelLogoutRequestError):
            self.id_token.send_backchannel_logout_request()

    def test_new_application_form_has_backchannel_logout_field(self):
        factory = RequestFactory()
        url = reverse("oauth2_provider:register")
        request = factory.get(url)
        request.user = self.user
        view = ApplicationRegistration(request=request)
        form = view.get_form()
        self.assertTrue("backchannel_logout_uri" in form.fields.keys())

    def test_logout_sender_does_not_crash_on_backchannel_error(self):
        with patch.object(self.id_token, "send_backchannel_logout_request") as mock_func:
            mock_func.side_effect = BackchannelLogoutRequestError("Bad Gateway")
            send_backchannel_logout_requests(self.user)
