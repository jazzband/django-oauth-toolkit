import pytest
from django.conf import settings as test_settings
from jwcrypto import jwk

from oauth2_provider.settings import oauth2_settings as _oauth2_settings


class OAuthSettingsWrapper:
    """
    A wrapper around oauth2_settings to ensure that when an overridden value is
    set, it also records it in _cached_attrs, so that the settings can be reset.
    """

    def __init__(self, settings, user_settings):
        if user_settings:
            settings.OAUTH2_PROVIDER = user_settings
        _oauth2_settings.reload()
        self.settings = settings
        # Reload OAuthlibCore for every view request during tests
        self.ALWAYS_RELOAD_OAUTHLIB_CORE = True

    def __setattr__(self, attr, value):
        setattr(_oauth2_settings, attr, value)
        _oauth2_settings._cached_attrs.add(attr)

    def __delattr__(self, attr):
        delattr(_oauth2_settings, attr)
        if attr in _oauth2_settings._cached_attrs:
            _oauth2_settings._cached_attrs.remove(attr)

    def __getattr__(self, attr):
        return getattr(_oauth2_settings, attr)

    def finalize(self):
        self.settings.finalize()
        _oauth2_settings.reload()


@pytest.fixture
def oauth2_settings(request, settings):
    """
    A fixture that provides a simple way to override OAUTH2_PROVIDER settings.

    It can be used two ways - either setting things on the fly, or by reading
    configuration data from the pytest marker oauth2_settings.

    If used on a standard pytest function, you can use argument dependency
    injection to get the wrapper. If used on a unittest.TestCase, the wrapper
    is made available on the class instance, as `oauth2_settings`.

    Anything overridden will be restored at the end of the test case, ensuring
    that there is no configuration leakage between test cases.
    """
    marker = request.node.get_closest_marker("oauth2_settings")
    user_settings = {}
    if marker is not None:
        user_settings = marker.args[0]
    wrapper = OAuthSettingsWrapper(settings, user_settings)
    if request.instance is not None:
        request.instance.oauth2_settings = wrapper
    yield wrapper
    wrapper.finalize()


@pytest.fixture(scope="class")
def oidc_key(request):
    request.cls.key = jwk.JWK.from_pem(test_settings.OIDC_RSA_PRIVATE_KEY.encode("utf8"))
