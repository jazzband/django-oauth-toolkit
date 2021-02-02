import json

from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from jwcrypto import jwk

from ..models import get_application_model
from ..settings import oauth2_settings
from .mixins import OAuthLibMixin, OIDCOnlyMixin


Application = get_application_model()


class ConnectDiscoveryInfoView(OIDCOnlyMixin, View):
    """
    View used to show oidc provider configuration information
    """

    def get(self, request, *args, **kwargs):
        issuer_url = oauth2_settings.OIDC_ISS_ENDPOINT

        if not issuer_url:
            issuer_url = oauth2_settings.oidc_issuer(request)
            authorization_endpoint = request.build_absolute_uri(reverse("oauth2_provider:authorize"))
            token_endpoint = request.build_absolute_uri(reverse("oauth2_provider:token"))
            userinfo_endpoint = oauth2_settings.OIDC_USERINFO_ENDPOINT or request.build_absolute_uri(
                reverse("oauth2_provider:user-info")
            )
            jwks_uri = request.build_absolute_uri(reverse("oauth2_provider:jwks-info"))
        else:
            authorization_endpoint = "{}{}".format(issuer_url, reverse("oauth2_provider:authorize"))
            token_endpoint = "{}{}".format(issuer_url, reverse("oauth2_provider:token"))
            userinfo_endpoint = oauth2_settings.OIDC_USERINFO_ENDPOINT or "{}{}".format(
                issuer_url, reverse("oauth2_provider:user-info")
            )
            jwks_uri = "{}{}".format(issuer_url, reverse("oauth2_provider:jwks-info"))
        signing_algorithms = [Application.HS256_ALGORITHM]
        if oauth2_settings.OIDC_RSA_PRIVATE_KEY:
            signing_algorithms = [Application.RS256_ALGORITHM, Application.HS256_ALGORITHM]
        data = {
            "issuer": issuer_url,
            "authorization_endpoint": authorization_endpoint,
            "token_endpoint": token_endpoint,
            "userinfo_endpoint": userinfo_endpoint,
            "jwks_uri": jwks_uri,
            "response_types_supported": oauth2_settings.OIDC_RESPONSE_TYPES_SUPPORTED,
            "subject_types_supported": oauth2_settings.OIDC_SUBJECT_TYPES_SUPPORTED,
            "id_token_signing_alg_values_supported": signing_algorithms,
            "token_endpoint_auth_methods_supported": (
                oauth2_settings.OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED
            ),
        }
        response = JsonResponse(data)
        response["Access-Control-Allow-Origin"] = "*"
        return response


class JwksInfoView(OIDCOnlyMixin, View):
    """
    View used to show oidc json web key set document
    """

    def get(self, request, *args, **kwargs):
        keys = []
        if oauth2_settings.OIDC_RSA_PRIVATE_KEY:
            key = jwk.JWK.from_pem(oauth2_settings.OIDC_RSA_PRIVATE_KEY.encode("utf8"))
            data = {"alg": "RS256", "use": "sig", "kid": key.thumbprint()}
            data.update(json.loads(key.export_public()))
            keys.append(data)
        response = JsonResponse({"keys": keys})
        response["Access-Control-Allow-Origin"] = "*"
        return response


@method_decorator(csrf_exempt, name="dispatch")
class UserInfoView(OIDCOnlyMixin, OAuthLibMixin, View):
    """
    View used to show Claims about the authenticated End-User
    """

    def get(self, request, *args, **kwargs):
        return self._create_userinfo_response(request)

    def post(self, request, *args, **kwargs):
        return self._create_userinfo_response(request)

    def _create_userinfo_response(self, request):
        url, headers, body, status = self.create_userinfo_response(request)
        response = HttpResponse(content=body or "", status=status)

        for k, v in headers.items():
            response[k] = v
        return response
