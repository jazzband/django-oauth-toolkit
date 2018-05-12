import json
from urllib.parse import urlparse, urlunparse

from oauthlib import oauth2
from oauthlib.common import quote, urlencode, urlencoded

from .exceptions import FatalClientError, OAuthToolkitError
from .settings import oauth2_settings


class OAuthLibCore(object):
    """
    TODO: add docs
    """
    def __init__(self, server=None):
        """
        :params server: An instance of oauthlib.oauth2.Server class
        """
        self.server = server or oauth2_settings.OAUTH2_SERVER_CLASS(oauth2_settings.OAUTH2_VALIDATOR_CLASS())

    def _get_escaped_full_path(self, request):
        """
        Django considers "safe" some characters that aren't so for oauthlib.
        We have to search for them and properly escape.
        """
        parsed = list(urlparse(request.get_full_path()))
        unsafe = set(c for c in parsed[4]).difference(urlencoded)
        for c in unsafe:
            parsed[4] = parsed[4].replace(c, quote(c, safe=b""))

        return urlunparse(parsed)

    def _get_extra_credentials(self, request):
        """
        Produce extra credentials for token response. This dictionary will be
        merged with the response.
        See also: `oauthlib.oauth2.rfc6749.TokenEndpoint.create_token_response`

        :param request: The current django.http.HttpRequest object
        :return: dictionary of extra credentials or None (default)
        """
        return None

    def _extract_params(self, request):
        """
        Extract parameters from the Django request object.
        Such parameters will then be passed to OAuthLib to build its own
        Request object. The body should be encoded using OAuthLib urlencoded.
        """
        uri = self._get_escaped_full_path(request)
        http_method = request.method
        headers = self.extract_headers(request)
        body = urlencode(self.extract_body(request))
        return uri, http_method, body, headers

    def extract_headers(self, request):
        """
        Extracts headers from the Django request object
        :param request: The current django.http.HttpRequest object
        :return: a dictionary with OAuthLib needed headers
        """
        headers = request.META.copy()
        if "wsgi.input" in headers:
            del headers["wsgi.input"]
        if "wsgi.errors" in headers:
            del headers["wsgi.errors"]
        if "HTTP_AUTHORIZATION" in headers:
            headers["Authorization"] = headers["HTTP_AUTHORIZATION"]

        return headers

    def extract_body(self, request):
        """
        Extracts the POST body from the Django request object
        :param request: The current django.http.HttpRequest object
        :return: provided POST parameters
        """
        return request.POST.items()

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

    def create_authorization_response(self, request, scopes, credentials, allow):
        """
        A wrapper method that calls create_authorization_response on `server_class`
        instance.

        :param request: The current django.http.HttpRequest object
        :param scopes: A list of provided scopes
        :param credentials: Authorization credentials dictionary containing
                           `client_id`, `state`, `redirect_uri`, `response_type`
        :param allow: True if the user authorize the client, otherwise False
        """
        try:
            if not allow:
                raise oauth2.AccessDeniedError(
                    state=credentials.get("state", None))

            # add current user to credentials. this will be used by OAUTH2_VALIDATOR_CLASS
            credentials["user"] = request.user

            headers, body, status = self.server.create_authorization_response(
                uri=credentials["redirect_uri"], scopes=scopes, credentials=credentials)
            uri = headers.get("Location", None)

            return uri, headers, body, status

        except oauth2.FatalClientError as error:
            raise FatalClientError(error=error, redirect_uri=credentials["redirect_uri"])
        except oauth2.OAuth2Error as error:
            raise OAuthToolkitError(error=error, redirect_uri=credentials["redirect_uri"])

    def create_token_response(self, request):
        """
        A wrapper method that calls create_token_response on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        uri, http_method, body, headers = self._extract_params(request)
        extra_credentials = self._get_extra_credentials(request)

        headers, body, status = self.server.create_token_response(uri, http_method, body,
                                                                  headers, extra_credentials)
        uri = headers.get("Location", None)

        return uri, headers, body, status

    def create_revocation_response(self, request):
        """
        A wrapper method that calls create_revocation_response on a
        `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        uri, http_method, body, headers = self._extract_params(request)

        headers, body, status = self.server.create_revocation_response(
            uri, http_method, body, headers)
        uri = headers.get("Location", None)

        return uri, headers, body, status

    def verify_request(self, request, scopes):
        """
        A wrapper method that calls verify_request on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        :param scopes: A list of scopes required to verify so that request is verified
        """
        uri, http_method, body, headers = self._extract_params(request)

        valid, r = self.server.verify_request(uri, http_method, body, headers, scopes=scopes)
        return valid, r


class JSONOAuthLibCore(OAuthLibCore):
    """
    Extends the default OAuthLibCore to parse correctly application/json requests
    """
    def extract_body(self, request):
        """
        Extracts the JSON body from the Django request object
        :param request: The current django.http.HttpRequest object
        :return: provided POST parameters "urlencodable"
        """
        try:
            body = json.loads(request.body.decode("utf-8")).items()
        except ValueError:
            body = ""

        return body


def get_oauthlib_core():
    """
    Utility function that take a request and returns an instance of
    `oauth2_provider.backends.OAuthLibCore`
    """
    validator = oauth2_settings.OAUTH2_VALIDATOR_CLASS()
    server = oauth2_settings.OAUTH2_SERVER_CLASS(validator)
    return oauth2_settings.OAUTH2_BACKEND_CLASS(server)
