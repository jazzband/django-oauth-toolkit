import pytest
from django.contrib.auth import get_user_model
from oauth2_provider.models import get_application_model

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase

Application = get_application_model()
User = get_user_model()


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
class TestBackchannelLogout(TestCase):
    def setUp(self):
        self.developer = User.objects.create_user(username="app_dev_user", password="123456")
        self.application = Application.objects.create(
            name="test_client_credentials_app",
            user=self.developer,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret="1234567890asdfghjkqwertyuiopzxcvbnm",
            backchannel_logout_uri="http://rp.example.com/logout",
        )

    def test_on_logout_token_is_sent(self):
        self.fail()
