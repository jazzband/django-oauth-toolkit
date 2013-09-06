import json

from oauthlib.oauth2 import Server
from ...backends import RestFrameworkOAuthLibCore
from ...oauth2_validators import OAuth2Validator
from ...views.mixins import OAuthLibMixin

from rest_framework.response import Response
from rest_framework.views import APIView


class TokenAPIView(OAuthLibMixin, APIView):
    """
    Implements an endpoint to provide access tokens.
    This view supports content-negotiation.

    The endpoint is used in the followin flows:
     * Authorization code
     * Implicit grant
     * Password
     * Client credentials
    """
    server_class = Server
    validator_class = OAuth2Validator
    oauthlib_core_class = RestFrameworkOAuthLibCore
    authentication_classes = ()
    permission_classes = ()


    def post(self, request, format=None):
        url, headers, body, status = self.create_token_response(request)
        data = json.loads(body)
        response = Response(data=data, status=status)

        for k, v in headers.items():
            response[k] = v
        return response
