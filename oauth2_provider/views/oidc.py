from __future__ import absolute_import, unicode_literals

import json

from django.http import JsonResponse
from django.urls import reverse_lazy
from django.views.generic import View
from jwcrypto import jwk

from ..settings import oauth2_settings


class ConnectDiscoveryInfoView(View):
    """
    View used to show oidc provider configuration information
    """
    def get(self, request, *args, **kwargs):
        issuer_url = oauth2_settings.OIDC_ISS_ENDPOINT
        data = {
            "issuer": issuer_url,
            "authorization_endpoint": "{}{}".format(issuer_url, reverse_lazy('oauth2_provider:authorize')),
            "token_endpoint": "{}{}".format(issuer_url, reverse_lazy('oauth2_provider:token')),
            "userinfo_endpoint": oauth2_settings.OIDC_USERINFO_ENDPOINT,
            "jwks_uri": "{}{}".format(issuer_url, reverse_lazy('oauth2_provider:jwks-info')),
            "response_types_supported": oauth2_settings.OIDC_RESPONSE_TYPES_SUPPORTED,
            "subject_types_supported": oauth2_settings.OIDC_SUBJECT_TYPES_SUPPORTED,
            "id_token_signing_alg_values_supported": oauth2_settings.OIDC_ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED,
            "token_endpoint_auth_methods_supported": oauth2_settings.OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
        }
        response = JsonResponse(data)
        response['Access-Control-Allow-Origin'] = '*'
        return response


class JwksInfoView(View):
    """
    View used to show oidc json web key set document
    """
    def get(self, request, *args, **kwargs):
        key = jwk.JWK.from_pem(oauth2_settings.OIDC_RSA_PRIVATE_KEY.encode("utf8"))
        data = {
            'keys': [{
                'alg': 'RS256',
                'use': 'sig',
                'kid': key.thumbprint()
            }]
        }
        data['keys'][0].update(json.loads(key.export_public()))
        response = JsonResponse(data)
        response['Access-Control-Allow-Origin'] = '*'
        return response
