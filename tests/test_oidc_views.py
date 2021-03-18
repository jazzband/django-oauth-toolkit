import pytest
from django.test import TestCase
from django.urls import reverse

from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestConnectDiscoveryInfoView(TestCase):
    def test_get_connect_discovery_info(self):
        expected_response = {
            "issuer": "http://localhost",
            "authorization_endpoint": "http://localhost/o/authorize/",
            "token_endpoint": "http://localhost/o/token/",
            "userinfo_endpoint": "http://localhost/userinfo/",
            "jwks_uri": "http://localhost/o/.well-known/jwks.json",
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "id_token token",
                "code token",
                "code id_token",
                "code id_token token",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        }
        response = self.client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_connect_discovery_info_without_issuer_url(self):
        self.oauth2_settings.OIDC_ISS_ENDPOINT = None
        self.oauth2_settings.OIDC_USERINFO_ENDPOINT = None
        expected_response = {
            "issuer": "http://testserver/o",
            "authorization_endpoint": "http://testserver/o/authorize/",
            "token_endpoint": "http://testserver/o/token/",
            "userinfo_endpoint": "http://testserver/o/userinfo/",
            "jwks_uri": "http://testserver/o/.well-known/jwks.json",
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "id_token token",
                "code token",
                "code id_token",
                "code id_token token",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        }
        response = self.client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_connect_discovery_info_without_rsa_key(self):
        self.oauth2_settings.OIDC_RSA_PRIVATE_KEY = None
        response = self.client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json()["id_token_signing_alg_values_supported"] == ["HS256"]


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestJwksInfoView(TestCase):
    def test_get_jwks_info(self):
        expected_response = {
            "keys": [
                {
                    "alg": "RS256",
                    "use": "sig",
                    "kid": "s4a1o8mFEd1tATAIH96caMlu4hOxzBUaI2QTqbYNBHs",
                    "e": "AQAB",
                    "kty": "RSA",
                    "n": "mwmIeYdjZkLgalTuhvvwjvnB5vVQc7G9DHgOm20Hw524bLVTk49IXJ2Scw42HOmowWWX-oMVT_ca3ZvVIeffVSN1-TxVy2zB65s0wDMwhiMoPv35z9IKHGMZgl9vlyso_2b7daVF_FQDdgIayUn8TQylBxEU1RFfW0QSYOBdAt8",  # noqa
                }
            ]
        }
        response = self.client.get(reverse("oauth2_provider:jwks-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_jwks_info_no_rsa_key(self):
        self.oauth2_settings.OIDC_RSA_PRIVATE_KEY = None
        response = self.client.get(reverse("oauth2_provider:jwks-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == {"keys": []}


@pytest.mark.django_db
@pytest.mark.parametrize("method", ["get", "post"])
def test_userinfo_endpoint(oidc_tokens, client, method):
    auth_header = "Bearer %s" % oidc_tokens.access_token
    rsp = getattr(client, method)(
        reverse("oauth2_provider:user-info"),
        HTTP_AUTHORIZATION=auth_header,
    )
    data = rsp.json()
    assert "sub" in data
    assert data["sub"] == str(oidc_tokens.user.pk)


@pytest.mark.django_db
def test_userinfo_endpoint_bad_token(oidc_tokens, client):
    # No access token
    rsp = client.get(reverse("oauth2_provider:user-info"))
    assert rsp.status_code == 401
    # Bad access token
    rsp = client.get(
        reverse("oauth2_provider:user-info"),
        HTTP_AUTHORIZATION="Bearer not-a-real-token",
    )
    assert rsp.status_code == 401


@pytest.mark.django_db
def test_userinfo_endpoint_custom_claims(oidc_tokens, client, oauth2_settings):
    class CustomValidator(OAuth2Validator):
        def get_additional_claims(self, request):
            return {"state": "very nice"}

    oidc_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    auth_header = "Bearer %s" % oidc_tokens.access_token
    rsp = client.get(
        reverse("oauth2_provider:user-info"),
        HTTP_AUTHORIZATION=auth_header,
    )
    data = rsp.json()
    assert "sub" in data
    assert data["sub"] == str(oidc_tokens.user.pk)
    assert "state" in data
    assert data["state"] == "very nice"
