from rest_framework.request import Request
from oauth2_provider import oauth2_backends


class OAuthLibCore(oauth2_backends.OAuthLibCore):
    """Backend for Django Rest Framework"""

    def extract_body(self, request):
        """
        We can read only once the body in Django, 
        so in case of DRF we avoid to read it before the framework does.
        This use case often happen during multipart form requests.

        NB: it forces you to use the `Authorization` request header 
            for authentication and not pass the credentials in the request body
        """
        if isinstance(request, Request):
            return request.data.items()
        return super(OAuthLibCore, self).extract_body(request)
