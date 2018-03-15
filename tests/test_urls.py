from __future__ import unicode_literals

from importlib import reload

from django.test import TestCase
from oauth2_provider.settings import oauth2_settings


class TestUrls(TestCase):
    def tearDown(self):
        oauth2_settings.ENABLE_APPLICATION_MANAGEMENT_VIEWS = True
        oauth2_settings.ENABLE_TOKEN_MANAGEMENT_VIEWS = True

    def test_disable_application_management_views(self):
        oauth2_settings.ENABLE_APPLICATION_MANAGEMENT_VIEWS = False
        import oauth2_provider.urls
        reload(oauth2_provider.urls)
        self.assertEquals(
            oauth2_provider.urls.urlpatterns,
            oauth2_provider.urls.base_urlpatterns + oauth2_provider.urls.token_management_urlpatterns
        )

    def test_disable_token_management_views(self):
        oauth2_settings.ENABLE_TOKEN_MANAGEMENT_VIEWS = False
        import oauth2_provider.urls
        reload(oauth2_provider.urls)
        self.assertEquals(
            oauth2_provider.urls.urlpatterns,
            oauth2_provider.urls.base_urlpatterns + oauth2_provider.urls.application_management_urlpatterns
        )

    def test_disable_both_views(self):
        oauth2_settings.ENABLE_APPLICATION_MANAGEMENT_VIEWS = False
        oauth2_settings.ENABLE_TOKEN_MANAGEMENT_VIEWS = False
        import oauth2_provider.urls
        reload(oauth2_provider.urls)
        self.assertEquals(
            oauth2_provider.urls.urlpatterns,
            oauth2_provider.urls.base_urlpatterns
        )
