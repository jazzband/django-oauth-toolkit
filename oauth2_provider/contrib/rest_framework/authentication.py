from collections import OrderedDict

from rest_framework.authentication import BaseAuthentication

from ...oauth2_backends import get_oauthlib_core


class OAuth2Authentication(BaseAuthentication):
    """
    OAuth 2 authentication backend using `django-oauth-toolkit`
    """

    www_authenticate_realm = "api"

    def _dict_to_string(self, my_dict):
        """
        Return a string of comma-separated key-value pairs (e.g. k="v",k2="v2").
        """
        return ",".join(['{k}="{v}"'.format(k=k, v=v) for k, v in my_dict.items()])

    def authenticate(self, request):
        """
        Returns two-tuple of (user, token) if authentication succeeds,
        or None otherwise.
        """
        oauthlib_core = get_oauthlib_core()
        valid, r = oauthlib_core.verify_request(request, scopes=[])
        if valid:
            return r.user, r.access_token
        request.oauth2_error = getattr(r, "oauth2_error", {})
        return None

    def authenticate_header(self, request):
        """
        Bearer is the only finalized type currently
        """
        www_authenticate_attributes = OrderedDict(
            [
                ("realm", self.www_authenticate_realm),
            ]
        )
        oauth2_error = getattr(request, "oauth2_error", {})
        www_authenticate_attributes.update(oauth2_error)
        return "Bearer {attributes}".format(
            attributes=self._dict_to_string(www_authenticate_attributes),
        )
