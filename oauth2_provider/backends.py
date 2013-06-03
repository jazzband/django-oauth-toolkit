from oauthlib import oauth2
from oauthlib.common import urlencode

from .exceptions import OAuthToolkitError, FatalClientError


class OAuthLibCore(object):
    """
    """
    def __init__(self, server):
        """
        :params server: An instance of oauthlib.oauth2.Server class
        """
        self.server = server

    def _extract_params(self, request):
        """
        Extract parameters from the Django request object. Such parameters will then be passed to OAuthLib to build its
        own Request object
        """
        uri = request.build_absolute_uri()
        http_method = request.method
        headers = request.META.copy()
        if 'wsgi.input' in headers:
            del headers['wsgi.input']
        if 'wsgi.errors' in headers:
            del headers['wsgi.errors']
        if 'HTTP_AUTHORIZATION' in headers:
            headers['Authorization'] = headers['HTTP_AUTHORIZATION']
        body = urlencode(request.POST.items())
        return uri, http_method, body, headers

    def validate_authorization_request(self, request):
        """
        A wrapper method that calls validate_authorization_request on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        try:
            uri, http_method, body, headers = self._extract_params(request)

            scopes, credentials = self.server.validate_authorization_request(
                uri, http_method=http_method, body=body, headers=headers)

            return scopes, credentials
        except oauth2.FatalClientError as error:
            raise FatalClientError(error=error)
        except oauth2.OAuth2Error as error:
            raise OAuthToolkitError(error=error)

    def create_authorization_response(self, scopes, credentials, allow):
        """
        A wrapper method that calls create_authorization_response on `server_class`
        instance.

        :param scopes: A list of provided scopes
        :param credentials: Authorization credentials dictionary containing
                           `client_id`, `state`, `redirect_uri`, `response_type`
        :param allow: True if the user authorize the client, otherwise False
        """
        try:
            if not allow:
                raise oauth2.AccessDeniedError()

            uri, headers, body, status = self.server.create_authorization_response(
                uri=credentials['redirect_uri'], scopes=scopes, credentials=credentials)

            return uri, headers, body, status

        except oauth2.FatalClientError as error:
            raise FatalClientError(error=error, redirect_uri=credentials['redirect_uri'])
        except oauth2.OAuth2Error as error:
            raise OAuthToolkitError(error=error, redirect_uri=credentials['redirect_uri'])

    def create_token_response(self, request):
        """
        A wrapper method that calls create_token_response on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        uri, http_method, body, headers = self._extract_params(request)

        url, headers, body, status = self.server.create_token_response(uri, http_method, body, headers)
        return url, headers, body, status

    def verify_request(self, request, scopes):
        """
        A wrapper method that calls verify_request on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        :param scopes: A list of scopes required to verify so that request is verified
        """
        uri, http_method, body, headers = self._extract_params(request)

        valid, r = self.server.verify_request(uri, http_method, body, headers, scopes=scopes)
        return valid, r