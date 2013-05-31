import logging

from django.views.generic import View, FormView
from django.http import HttpResponse, HttpResponseRedirect

from oauthlib.oauth2 import Server

from braces.views import LoginRequiredMixin, CsrfExemptMixin

from .exceptions import OAuthToolkitError
from .forms import AllowForm
from .mixins import OAuthLibMixin, ProtectedResourceMixin, ScopedResourceMixin
from .models import Application
from .oauth2_validators import OAuth2Validator


log = logging.getLogger('oauth2_provider')


class BaseAuthorizationView(LoginRequiredMixin, OAuthLibMixin, View):
    """

    """
    def dispatch(self, request, *args, **kwargs):
        self.oauth2_data = {}
        return super(BaseAuthorizationView, self).dispatch(request, *args, **kwargs)

    def error_response(self, error, **kwargs):
        """
        """
        redirect, error_response = super(BaseAuthorizationView, self).error_response(error, **kwargs)

        if redirect:
            return HttpResponseRedirect(error_response['url'])

        status = error_response['error'].status_code
        return self.render_to_response(error_response, status=status)


class AuthorizationView(BaseAuthorizationView, FormView):
    """
    """
    template_name = 'oauth2_provider/authorize.html'
    form_class = AllowForm

    server_class = Server
    validator_class = OAuth2Validator

    def get_initial(self):
        # TODO: move this scopes conversion from and to string into a utils function
        scopes = self.oauth2_data.get('scopes', [])
        initial_data = {
            'redirect_uri': self.oauth2_data.get('redirect_uri', None),
            'scopes': ' '.join(scopes),
            'client_id': self.oauth2_data.get('client_id', None),
            'state': self.oauth2_data.get('state', None),
            'response_type': self.oauth2_data.get('response_type', None),
        }
        return initial_data

    def form_valid(self, form):
        try:
            credentials = {
                'client_id': form.cleaned_data.get('client_id'),
                'redirect_uri': form.cleaned_data.get('redirect_uri'),
                'response_type': form.cleaned_data.get('response_type', None),
                'state': form.cleaned_data.get('state', None),
            }

            scopes = form.cleaned_data.get('scopes')
            allow = form.cleaned_data.get('allow')
            uri, headers, body, status = self.create_authorization_response(
                request=self.request, scopes=scopes, credentials=credentials, allow=allow)
            self.success_url = uri
            log.debug("Success url for the request: {0}".format(self.success_url))
            return super(AuthorizationView, self).form_valid(form)

        except OAuthToolkitError as error:
            return self.error_response(error)

    def get(self, request, *args, **kwargs):
        try:
            scopes, credentials = self.validate_authorization_request(request)
            kwargs['scopes'] = scopes
            # at this point we know an Application instance with such client_id exists in the database
            kwargs['application'] = Application.objects.get(client_id=credentials['client_id'])  # TODO: this should be cached one day
            kwargs.update(credentials)
            self.oauth2_data = kwargs
            # following code is here only because of https://code.djangoproject.com/ticket/17795
            form = self.get_form(self.get_form_class())
            kwargs['form'] = form
            return self.render_to_response(self.get_context_data(**kwargs))

        except OAuthToolkitError as error:
            return self.error_response(error)


class TokenView(CsrfExemptMixin, OAuthLibMixin, View):
    """
    """
    server_class = Server
    validator_class = OAuth2Validator

    def post(self, request, *args, **kwargs):
        url, headers, body, status = self.create_token_response(request)
        response = HttpResponse(content=body, status=status)

        for k, v in headers.items():
            response[k] = v
        return response


class ProtectedResourceView(ProtectedResourceMixin, View):
    """
    """
    server_class = Server
    validator_class = OAuth2Validator


class ScopeProtectedResourceView(ScopedResourceMixin, ProtectedResourceView):
    """
    """
