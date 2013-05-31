import logging

from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseForbidden

from oauthlib.common import urlencode
from oauthlib import oauth2

from ..exceptions import OAuthToolkitError


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
        try:
            uri, http_method, body, headers = self._extract_params(request)

            server = self.get_server(request)
            scopes, credentials = server.validate_authorization_request(
                uri, http_method=http_method, body=body, headers=headers)

            return scopes, credentials
        except oauth2.OAuth2Error as error:
            raise OAuthToolkitError(error=error)

    def create_authorization_response(self, request, scopes, credentials, allow):
        """
        A wrapper methods that calls create_authorization_response on `server_class`
        instance.

        :param request: The current django.http.HttpRequest object
        :param scopes: A space-separated string of provided scopes
        :param credentials: Authorization credentials dictionary containing
                           `client_id`, `state`, `redirect_uri`, `response_type`
        :param allow: True if the user authorize the client, otherwise False
        """
        try:
            if not allow:
                raise oauth2.AccessDeniedError()

            # TODO: move this scopes conversion from and to string into a utils function
            scopes = scopes.split(" ") if scopes else []

            server = self.get_server(request)
            uri, headers, body, status = server.create_authorization_response(
                uri=credentials['redirect_uri'], scopes=scopes, credentials=credentials)

            return uri, headers, body, status

        except oauth2.OAuth2Error as error:
            raise OAuthToolkitError(error=error, redirect_uri=credentials['redirect_uri'])

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
        valid, r = server.verify_request(uri, http_method, body, headers, scopes=self.get_scopes())

        return valid, r

    def get_scopes(self):
        """
        This should return the list of scopes required to access the resources. By default
        it returns an empty list
        """
        return []

    def error_response(self, error, **kwargs):
        """
        Return an error to be displayed to the resource owner if anything goes awry.

        :param error: :attr:`OAuthToolkitError`
        """
        error = error.oauthlib_error
        error_response = {
            'error': error,
            'url': "{0}?{1}".format(error.redirect_uri, error.urlencoded)
        }
        error_response.update(kwargs)

        # If we got a malicious redirect_uri or client_id, we will *not* redirect back to the URL.
        if isinstance(error, oauth2.FatalClientError):
            redirect = False
        else:
            redirect = True

        return redirect, error_response


class ScopedResourceMixin(object):
    """
    Helper mixin that handles scopes
    """
    requested_scopes = None

    def get_scopes(self, *args, **kwargs):
        """
        Return the scopes needed to access the resource
        """
        if self.requested_scopes is None:
            raise ImproperlyConfigured(
                "ProtectedResourceMixin requires either a definition of 'requested_scopes'"
                " or an implementation of 'get_scopes()'")
        else:
            return self.requested_scopes


class ProtectedResourceMixin(OAuthLibMixin):
    """
    """
    def dispatch(self, request, *args, **kwargs):
        valid, r = self.verify_request(request)
        if valid:
            return super(ProtectedResourceMixin, self).dispatch(request, *args, **kwargs)
        else:
            return HttpResponseForbidden()
