import logging

from django.views.generic import View, FormView
from django.http import HttpResponse, HttpResponseForbidden

from oauthlib.oauth2 import Server
from oauthlib.oauth2 import errors

from braces.views import LoginRequiredMixin, CsrfExemptMixin

from .oauth2_validators import OAuth2Validator
from .models import Application
from .forms import AllowForm
from .mixins import OAuthLibMixin


log = logging.getLogger('oauth2_provider')


class OAuth2Mixin(OAuthLibMixin):
    """

    """
    def dispatch(self, request, *args, **kwargs):
        self.oauth2_data = {}
        return super(OAuth2Mixin, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        # TODO: this method assumes we are using FormMixin. Move this code away
        # this method is here only because of https://code.djangoproject.com/ticket/17795
        form = self.get_form(self.get_form_class())
        kwargs['form'] = form
        return self.render_to_response(self.get_context_data(**kwargs))


class PreAuthorizationMixin(LoginRequiredMixin, OAuth2Mixin):
    """

    """
    def get(self, request, *args, **kwargs):
        try:
            scopes, credentials = self.validate_authorization_request(request)
            kwargs['scopes'] = scopes
            # at this point we know an Application instance with such client_id exists in the database
            kwargs['application'] = Application.objects.get(client_id=credentials['client_id'])  # TODO: this should be cached one day
            kwargs.update(credentials)
            self.oauth2_data = kwargs
            return super(PreAuthorizationMixin, self).get(request, *args, **kwargs)

        except errors.OAuth2Error as e:
            return self.error_response(e, **kwargs)


class AuthorizationCodeView(PreAuthorizationMixin, FormView):
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
        redirect_uri = form.cleaned_data.get('redirect_uri')
        try:
            if not form.cleaned_data.get('allow'):
                raise errors.AccessDeniedError()

            credentials = {
                'client_id': form.cleaned_data.get('client_id'),
                'redirect_uri': form.cleaned_data.get('redirect_uri'),
                'response_type': form.cleaned_data.get('response_type', None),
                'state': form.cleaned_data.get('state', None),
            }

            scopes = form.cleaned_data.get('scopes')
            uri, headers, body, status = self.create_authorization_response(
                request=self.request, scopes=scopes, credentials=credentials)
            self.success_url = uri
            log.debug("Success url for the request: {0}".format(self.success_url))
            return super(AuthorizationCodeView, self).form_valid(form)

        except errors.OAuth2Error as e:
            return self.error_response(e, redirect_uri=redirect_uri)


class TokenView(CsrfExemptMixin, OAuth2Mixin, View):
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


class ProtectedResourceMixin(OAuth2Mixin):
    """
    """
    server_class = Server
    validator_class = OAuth2Validator

    def dispatch(self, request, *args, **kwargs):
        valid, r = self.verify_request(request)
        if valid:
            return super(ProtectedResourceMixin, self).dispatch(request, *args, **kwargs)
        else:
            return HttpResponseForbidden()
