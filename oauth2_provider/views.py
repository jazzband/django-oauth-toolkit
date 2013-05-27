import logging

from django.views.generic import FormView
from django.http import HttpResponseRedirect
from oauthlib.common import urlencode
from oauthlib.oauth2 import Server
from oauthlib.oauth2 import errors

from braces.views import LoginRequiredMixin

from .oauth2_validators import OAuth2Validator
from .models import Application
from .forms import AllowForm


log = logging.getLogger('oauth2_provider')


class OAuth2Mixin(object):
    """

    """
    def _extract_params(self, request):
        log.debug('Extracting parameters from request.')
        uri = request.build_absolute_uri()
        http_method = request.method
        headers = request.META
        if 'wsgi.input' in headers:
            del headers['wsgi.input']
        if 'wsgi.errors' in headers:
            del headers['wsgi.errors']
        if 'HTTP_AUTHORIZATION' in headers:
            headers['Authorization'] = headers['HTTP_AUTHORIZATION']
        body = urlencode(request.POST.items())
        return uri, http_method, body, headers

    def error_response(self, error, uri=None, **kwargs):
        """
        Return an error to be displayed to the resource owner if anything goes
        awry. Errors can include invalid clients, authorization denials and
        other edge cases such as a wrong ``redirect_uri`` in the authorization
        request.

        :param error: :attr:`oauthlib.errors.OAuth2Error`
        :param uri: ``dict``
            The different types of errors are outlined in :draft:`4.2.2.1`
        """

        # If we got a malicious redirect_uri or client_id, remove all the
        # cached data and tell the resource owner. We will *not* redirect back
        # to the URL.
        if isinstance(error, errors.FatalClientError):
            return self.render_to_response({'error': error}, status=error.status_code, **kwargs)

        url = self.server.create_authorization_response(uri, scopes=[''])
        return HttpResponseRedirect(url[0])


class PreAuthorizationMixin(OAuth2Mixin):
    """

    """
    def dispatch(self, request, *args, **kwargs):
        self.server = Server(OAuth2Validator(request.user))
        uri, http_method, body, headers = self._extract_params(request)
        try:
            scopes, credentials = self.server.validate_authorization_request(uri, http_method, body, headers)
            kwargs['scopes'] = scopes
            # at this point we know an Application instance with such client_id exists in the database
            kwargs['application'] = Application.objects.get(client_id=credentials['client_id'])  # TODO: this should be cached one day
            kwargs.update(credentials)
            self.oauth2_data = kwargs
            self.oauth2_data['user_id'] = request.user.id
            return super(PreAuthorizationMixin, self).dispatch(request, *args, **kwargs)

        except errors.OAuth2Error as e:
            return self.error_response(e, uri, **kwargs)


class AuthorizationCodeView(LoginRequiredMixin, PreAuthorizationMixin, FormView):
    """

    """
    template_name = 'oauth2_provider/authorize.html'
    form_class = AllowForm

    def get(self, request, *args, **kwargs):
        # this method is here only because of https://code.djangoproject.com/ticket/17795
        form = self.get_form(self.get_form_class())
        kwargs['form'] = form
        return self.render_to_response(self.get_context_data(**kwargs))

    def post(self, request, *args, **kwargs):
        try:
            return super(AuthorizationCodeView, self).post(request, *args, **kwargs)
        except errors.FatalClientError as e:
            return self.error_response(e, **kwargs)

    def get_initial(self):
        initial_data = {
            'redirect_uri': self.oauth2_data.get('redirect_uri', None),
            'scopes': self.oauth2_data.get('scopes', None),
            'client_id': self.oauth2_data.get('client_id', None),
            'state': self.oauth2_data.get('state', None),
            'user_id': self.oauth2_data.get('user_id'),
        }
        return initial_data

    def get_success_url(self):
        credentials = {
            'client_id': self.oauth2_data.get('client_id'),
            'redirect_uri': self.oauth2_data.get('redirect_uri'),
            'response_type': self.oauth2_data.get('response_type', None),
            'state': self.oauth2_data.get('state', None),
        }
        url = self.server.create_authorization_response(uri=self.oauth2_data.get('redirect_uri'),
                                                        scopes=self.oauth2_data.get('scopes'), credentials=credentials)
        log.debug("Success url for the request: {0}".format(url))
        return url[0]
