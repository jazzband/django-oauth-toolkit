import logging
import datetime

from django.http import HttpResponse, HttpResponseRedirect
from django.views.generic import View, FormView

from oauthlib.oauth2 import Server

from braces.views import LoginRequiredMixin, CsrfExemptMixin

from ..settings import oauth2_settings
from ..exceptions import OAuthToolkitError
from ..forms import AllowForm
from ..models import get_application_model
from ..oauth2_validators import OAuth2Validator
from .mixins import OAuthLibMixin

Application = get_application_model()

log = logging.getLogger('oauth2_provider')


class BaseAuthorizationView(LoginRequiredMixin, OAuthLibMixin, View):
    """
    Implements a generic endpoint to handle *Authorization Requests* as in :rfc:`4.1.1`. The view does not implement
    any strategy to determine *authorize/do not authorize* logic.
    The endpoint is used in the following flows:
     * Authorization code
     * Implicit grant
    """
    def dispatch(self, request, *args, **kwargs):
        self.oauth2_data = {}
        return super(BaseAuthorizationView, self).dispatch(request, *args, **kwargs)

    def error_response(self, error, **kwargs):
        """
        Handle errors either by redirecting to redirect_uri with a json in the body containing error details or
        providing an error response
        """
        redirect, error_response = super(BaseAuthorizationView, self).error_response(error, **kwargs)

        if redirect:
            return HttpResponseRedirect(error_response['url'])

        status = error_response['error'].status_code
        return self.render_to_response(error_response, status=status)


class AuthorizationView(BaseAuthorizationView, FormView):
    """
    Implements and endpoint to handle *Authorization Requests* as in :rfc:`4.1.1` and prompting the user with a form
    to determine if she authorizes the client application to access her data. This endpoint is reached two times during
    the authorization process:
     * first receive a ``GET`` request from user asking authorization for a certain client application, a form is served
     possibly showing some useful info and prompting for *authorize/do not authorize*.

     * then receive a ``POST`` request possibly after user authorized the access

    Some informations contained in the ``GET`` request and needed to create a Grant token during the ``POST`` request
    would be lost between the two steps above, so they are temporary stored in hidden fields on the form.
    A possible alternative could be keeping such informations in the session.

    The endpoint is used in the followin flows:
     * Authorization code
     * Implicit grant
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
            kwargs['scopes_descriptions'] = [oauth2_settings.SCOPES[scope] for scope in scopes]
            kwargs['scopes'] = scopes
            # at this point we know an Application instance with such client_id exists in the database
            kwargs['application'] = Application.objects.get(client_id=credentials['client_id'])  # TODO: cache it!
            kwargs.update(credentials)
            self.oauth2_data = kwargs
            # following code is here only because of https://code.djangoproject.com/ticket/17795
            form = self.get_form(self.get_form_class())
            kwargs['form'] = form

            # Check to see if the user has already granted access and return
            # a successful response
            require_approval = request.get('approval_prompt', 'auto') == 'auto'
            if not require_approval and request.user.accesstoken_set.filter(
                        application=kwargs['application'],
                        expires__gt=datetime.datetime.now()).count():
                uri, headers, body, status = self.create_authorization_response(
                        request=self.request, scopes=" ".join(scopes),
                        credentials=credentials, allow=True)
                self.success_url = uri
                return HttpResponseRedirect(self.success_url)
            return self.render_to_response(self.get_context_data(**kwargs))

        except OAuthToolkitError as error:
            return self.error_response(error)


class TokenView(CsrfExemptMixin, OAuthLibMixin, View):
    """
    Implements an endpoint to provide access tokens

    The endpoint is used in the followin flows:
     * Authorization code
     * Password
     * Client credentials
    """
    server_class = Server
    validator_class = OAuth2Validator

    def post(self, request, *args, **kwargs):
        url, headers, body, status = self.create_token_response(request)
        response = HttpResponse(content=body, status=status)

        for k, v in headers.items():
            response[k] = v
        return response
