from django.test import TestCase
from django.test.utils import override_settings

from oauth2_provider.admin import (
    get_access_token_admin_class,
    get_application_admin_class,
    get_grant_admin_class,
    get_refresh_token_admin_class,
)
from oauth2_provider.settings import OAuth2ProviderSettings, oauth2_settings
from tests.admin import (
    CustomAccessTokenAdmin,
    CustomApplicationAdmin,
    CustomGrantAdmin,
    CustomRefreshTokenAdmin,
)


class TestAdminClass(TestCase):
    def test_import_error_message_maintained(self):
        """
        Make sure import errors are captured and raised sensibly.
        """
        settings = OAuth2ProviderSettings({"CLIENT_ID_GENERATOR_CLASS": "invalid_module.InvalidClassName"})
        with self.assertRaises(ImportError):
            settings.CLIENT_ID_GENERATOR_CLASS

    def test_get_application_admin_class(self):
        """
        Test for getting class for application admin.
        """
        application_admin_class = get_application_admin_class()
        default_application_admin_class = oauth2_settings.APPLICATION_ADMIN_CLASS
        assert application_admin_class == default_application_admin_class

    def test_get_access_token_admin_class(self):
        """
        Test for getting class for access token admin.
        """
        access_token_admin_class = get_access_token_admin_class()
        default_access_token_admin_class = oauth2_settings.ACCESS_TOKEN_ADMIN_CLASS
        assert access_token_admin_class == default_access_token_admin_class

    def test_get_grant_admin_class(self):
        """
        Test for getting class for grant admin.
        """
        grant_admin_class = get_grant_admin_class()
        default_grant_admin_class = oauth2_settings.GRANT_ADMIN_CLASS
        assert grant_admin_class, default_grant_admin_class

    def test_get_refresh_token_admin_class(self):
        """
        Test for getting class for refresh token admin.
        """
        refresh_token_admin_class = get_refresh_token_admin_class()
        default_refresh_token_admin_class = oauth2_settings.REFRESH_TOKEN_ADMIN_CLASS
        assert refresh_token_admin_class == default_refresh_token_admin_class

    @override_settings(OAUTH2_PROVIDER={"APPLICATION_ADMIN_CLASS": "tests.admin.CustomApplicationAdmin"})
    def test_get_custom_application_admin_class(self):
        """
        Test for getting custom class for application admin.
        """
        application_admin_class = get_application_admin_class()
        assert application_admin_class == CustomApplicationAdmin

    @override_settings(OAUTH2_PROVIDER={"ACCESS_TOKEN_ADMIN_CLASS": "tests.admin.CustomAccessTokenAdmin"})
    def test_get_custom_access_token_admin_class(self):
        """
        Test for getting custom class for access token admin.
        """
        access_token_admin_class = get_access_token_admin_class()
        assert access_token_admin_class == CustomAccessTokenAdmin

    @override_settings(OAUTH2_PROVIDER={"GRANT_ADMIN_CLASS": "tests.admin.CustomGrantAdmin"})
    def test_get_custom_grant_admin_class(self):
        """
        Test for getting custom class for grant admin.
        """
        grant_admin_class = get_grant_admin_class()
        assert grant_admin_class == CustomGrantAdmin

    @override_settings(OAUTH2_PROVIDER={"REFRESH_TOKEN_ADMIN_CLASS": "tests.admin.CustomRefreshTokenAdmin"})
    def test_get_custom_refresh_token_admin_class(self):
        """
        Test for getting custom class for refresh token admin.
        """
        refresh_token_admin_class = get_refresh_token_admin_class()
        assert refresh_token_admin_class == CustomRefreshTokenAdmin
