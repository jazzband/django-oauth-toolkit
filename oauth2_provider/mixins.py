import logging

from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseRedirect

from oauthlib.common import urlencode
from oauthlib.oauth2 import errors


log = logging.getLogger("oauth2_provider")


class OAuthLibMixin(object):
    """
    """
    server_class = None
    validator_class = None

    def get_server_class(self):
        """
        Return the OAuthlib server class to use
        """
        if self.server_class is None:
            raise ImproperlyConfigured(
                "OAuthLibMixin requires either a definition of 'server_class'"
                " or an implementation of 'get_server_class()'")
        else:
            return self.server_class

    def get_validator_class(self):
        """
        Return the RequestValidator implementation class to use
        """
        if self.validator_class is None:
            raise ImproperlyConfigured(
                "OAuthLibMixin requires either a definition of 'validator_class'"
                " or an implementation of 'get_validator_class()'")
        else:
            return self.validator_class

    def get_server(self, request):
        """
        Return an instance of `server_class` initialized with a `validator_class`
        object
        """
        server_class = self.get_server_class()
        validator_class = self.get_validator_class()
        return server_class(validator_class(request.user))

    def _extract_params(self, request):
        """

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
        A wrapper methods that calls validate_authorization_request on `server_class`
        instance.

        :param request: The current django.http.HttpRequest object
        """
        uri, http_method, body, headers = self._extract_params(request)

        server = self.get_server(request)
        scopes, credentials = server.validate_authorization_request(
            uri, http_method=http_method, body=body, headers=headers)

        return scopes, credentials

    def create_authorization_response(self, request, scopes, credentials):
        """
        A wrapper methods that calls create_authorization_response on `server_class`
        instance.

        :param request: The current django.http.HttpRequest object
        :param scopes: A space-separated string of provided scopes
        :param credentials: Authorization credentials dictionary containing
                           `client_id`, `state`, `redirect_uri`, `response_type`
        """
        # TODO: move this scopes conversion from and to string into a utils function
        scopes = scopes.split(" ") if scopes else []

        server = self.get_server(request)
        uri, headers, body, status = server.create_authorization_response(
            uri=credentials['redirect_uri'], scopes=scopes, credentials=credentials)

        return uri, headers, body, status

    def create_token_response(self, request):
        """
        A wrapper methods that calls create_token_response on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        uri, http_method, body, headers = self._extract_params(request)

        server = self.get_server(request)
        url, headers, body, status = server.create_token_response(
            uri, http_method, body, headers)

        return url, headers, body, status

    def verify_request(self, request):
        """
        A wrapper methods that calls verify_request on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        uri, http_method, body, headers = self._extract_params(request)

        server = self.get_server(request)
        # TODO: we need to pass a list of scopes requested by the protected resource
        valid, r = server.verify_request(uri, http_method, body, headers, scopes=None)

        return valid, r

    def error_response(self, error, uri=None, redirect_uri=None, **kwargs):
        """
        Return an error to be displayed to the resource owner if anything goes awry.

        :param error: :attr:`oauthlib.errors.OAuth2Error`
        :param uri: ``dict``
            The different types of errors are outlined in :draft:`4.2.2.1`
        """

        # If we got a malicious redirect_uri or client_id, remove all the
        # cached data and tell the resource owner. We will *not* redirect back
        # to the URL.
        # TODO: this method assumes the class has a render_to_response error
        if isinstance(error, errors.FatalClientError):
            return self.render_to_response({'error': error}, status=error.status_code, **kwargs)

        if redirect_uri:
            url = "{0}?{1}".format(redirect_uri, error.urlencoded)
        else:
            url = self.create_authorization_response(uri, scopes="")[0]
        return HttpResponseRedirect(url)
