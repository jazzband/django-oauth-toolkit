from braces.views import CsrfExemptMixin
from django.http import HttpResponse
from django.views.generic import View
import json

from ..utils import build_claims_doc
from ..settings import oauth2_settings
from ..views.mixins import ProtectedResourceMixin, ScopedResourceMixin
from ..exceptions import UnsupportedResponseTypeError


class UserInfoView(CsrfExemptMixin, ScopedResourceMixin, ProtectedResourceMixin, View):
    """
    Implements an endpoint to provide UserInfo

    The endpoint is used in the following flows:
    * OpenId Connect UserInfo
    """
    server_class = oauth2_settings.OAUTH2_SERVER_CLASS
    validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
    oauthlib_backend_class = oauth2_settings.OAUTH2_BACKEND_CLASS

    required_scopes = ['openid']

    def get(self, request, *args, **kwargs):
        return self._handle(request, request.GET.get('format', 'application/json'), *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self._handle(request, request.POST.get('format', 'application/json'), *args, **kwargs)

    def get_user_info_data(self, user, client, scopes, request=None, oauthlib_request=None):
        user_info_data = {"sub": user.pk}
        claims_provider = self._get_user_claims_provider()

        if claims_provider and oauthlib_request.access_token.claims:
            claims_doc = build_claims_doc(scopes, oauthlib_request.access_token.claims, claims_location="userinfo")

            claims = claims_provider.get_claims(user, client, claims_doc, oauthlib_request)
            if claims:
                user_info_data.update(claims)

    def _get_user_claims_provider(self):
        if not hasattr(self, "_user_claims_provider"):
            self._user_claims_provider = oauth2_settings.OPENID_USER_CLAIMS_PROVIDER_CLASS()
        return self._user_claims_provider

    def populate_user_info(self, user_info_data, user, client, scopes, request=None, oauthlib_request=None):
        # Subclasses should override this method to extend the user info data with any scopes the token authorizes.
        raise user_info_data

    def _handle(self, request, format, *args, **kwargs):

        # From ProtectedResourceMixin
        oauthlib_request = request.oauthlib_request

        # at this point oauthlib_request is going to have these attributes populated
        #   token_type - Bearer
        #   client - the oauth2_provider.models.Application instance
        #   user - the UserModel instance
        #   scopes - a space-separated list of scopes the token is authorized to access
        #   access_token - the oauth2_provider.models.AccessToken instance

        body = self.get_user_info_data(oauthlib_request.user, oauthlib_request.client,
                                       oauthlib_request.scopes, request=request, oauthlib_request=oauthlib_request)

        serialized_body = None
        if format == 'application/jwt':
            try:
                from jose import jws
                serialized_body = jws.sign(body, oauthlib_request.client.secret, oauth2_settings.OPENID_CONNECT_ID_TOKEN_ALG)
            except Exception as ex:
                raise UnsupportedResponseTypeError(error="Unsupported response format requested: application/jwt")
        else:
            serialized_body = json.dumps(body)

        response = HttpResponse(content=serialized_body, status=200)

        return response



