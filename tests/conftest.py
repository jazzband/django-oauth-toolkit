from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from django.conf import settings as test_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from jwcrypto import jwk

from oauth2_provider.models import get_application_model
from oauth2_provider.settings import oauth2_settings as _oauth2_settings

from . import presets


Application = get_application_model()
UserModel = get_user_model()


class OAuthSettingsWrapper:
    """
    A wrapper around oauth2_settings to ensure that when an overridden value is
    set, it also records it in _cached_attrs, so that the settings can be reset.
    """

    def __init__(self, settings, user_settings):
        self.settings = settings
        if not user_settings:
            user_settings = {}
        self.update(user_settings)

    def update(self, user_settings):
        self.settings.OAUTH2_PROVIDER = user_settings
        _oauth2_settings.reload()
        # Reload OAuthlibCore for every view request during tests
        self.ALWAYS_RELOAD_OAUTHLIB_CORE = True

    def __setattr__(self, attr, value):
        if attr == "settings":
            super().__setattr__(attr, value)
        else:
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


@pytest.fixture(scope="session")
def oidc_key_():
    return jwk.JWK.from_pem(test_settings.OIDC_RSA_PRIVATE_KEY.encode("utf8"))


@pytest.fixture
def oidc_key(request, oidc_key_):
    if request.instance is not None:
        request.instance.key = oidc_key_
    return oidc_key_


@pytest.fixture
def application():
    return Application.objects.create(
        name="Test Application",
        redirect_uris="http://example.org",
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        algorithm=Application.RS256_ALGORITHM,
    )


@pytest.fixture
def hybrid_application(application):
    application.authorization_grant_type = application.GRANT_OPENID_HYBRID
    application.save()
    return application


@pytest.fixture
def test_user():
    return UserModel.objects.create_user("test_user", "test@example.com", "123456")


@pytest.fixture
def oidc_tokens(oauth2_settings, application, test_user, client):
    oauth2_settings.update(presets.OIDC_SETTINGS_RW)
    client.force_login(test_user)
    auth_rsp = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": application.client_id,
            "state": "random_state_string",
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        },
    )
    assert auth_rsp.status_code == 302
    code = parse_qs(urlparse(auth_rsp["Location"]).query)["code"]
    client.logout()
    token_rsp = client.post(
        reverse("oauth2_provider:token"),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://example.org",
            "client_id": application.client_id,
            "client_secret": application.client_secret,
            "scope": "openid",
        },
    )
    assert token_rsp.status_code == 200
    token_data = token_rsp.json()
    return SimpleNamespace(
        user=test_user,
        application=application,
        access_token=token_data["access_token"],
        id_token=token_data["id_token"],
        oauth2_settings=oauth2_settings,
    )
