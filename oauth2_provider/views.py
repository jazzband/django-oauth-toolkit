import logging

from django.views.generic import View, FormView
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden
from oauthlib.common import urlencode
from oauthlib.oauth2 import Server
from oauthlib.oauth2 import errors

from braces.views import LoginRequiredMixin, CsrfExemptMixin

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

    def dispatch(self, request, *args, **kwargs):
        self.server = Server(OAuth2Validator(request.user))
        self.oauth2_data = {}
        return super(OAuth2Mixin, self).dispatch(request, *args, **kwargs)

    def error_response(self, error, uri=None, redirect_uri=None, **kwargs):
        """
        Return an error to be displayed to the resource owner if anything goes
        awry. Errors can include invalid clients, authorization denials and
        other edge cases such as a wrong ``redirect_uri`` in the authorization
        request.

        :param error: :attr:`oauthlib.errors.OAuth2Error`
        :param uri: ``dict``
            The different types of errors are outlined in :rfc:`4.2.2.1`
        """

        # If we got a malicious redirect_uri or client_id, remove all the
        # cached data and tell the resource owner. We will *not* redirect back
        # to the URL.
        if isinstance(error, errors.FatalClientError):
            return self.render_to_response({'error': error}, status=error.status_code, **kwargs)

        if redirect_uri:
            url = "{0}?{1}".format(redirect_uri, error.urlencoded)
        else:
            url = self.server.create_authorization_response(uri, scopes=[''])[0]
        return HttpResponseRedirect(url)

    def get(self, request, *args, **kwargs):
        # this method is here only because of https://code.djangoproject.com/ticket/17795
        form = self.get_form(self.get_form_class())
        kwargs['form'] = form
        return self.render_to_response(self.get_context_data(**kwargs))


class PreAuthorizationMixin(LoginRequiredMixin, OAuth2Mixin):
    """

    """
    def get(self, request, *args, **kwargs):
        uri, http_method, body, headers = self._extract_params(request)
        try:
            scopes, credentials = self.server.validate_authorization_request(uri, http_method, body, headers)
            kwargs['scopes'] = scopes
            # at this point we know an Application instance with such client_id exists in the database
            kwargs['application'] = Application.objects.get(client_id=credentials['client_id'])  # TODO: this should be cached one day
            kwargs.update(credentials)
            self.oauth2_data = kwargs
            return super(PreAuthorizationMixin, self).get(request, *args, **kwargs)

        except errors.OAuth2Error as e:
            return self.error_response(e, uri, **kwargs)


class AuthorizationCodeView(PreAuthorizationMixin, FormView):
    """

    """
    template_name = 'oauth2_provider/authorize.html'
    form_class = AllowForm

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

            # TODO: move this scopes conversion from and to string into a utils function
            scopes = form.cleaned_data.get('scopes')
            if scopes:
               scopes = scopes.split(" ")

            url = self.server.create_authorization_response(
                uri=form.cleaned_data.get('redirect_uri'),
                scopes=scopes,
                credentials=credentials)
            self.success_url = url[0]
            log.debug("Success url for the request: {0}".format(self.success_url))
            return super(AuthorizationCodeView, self).form_valid(form)

        except errors.FatalClientError as e:
            return self.error_response(e)
        except errors.OAuth2Error as e:
            return self.error_response(e, redirect_uri=redirect_uri)


class TokenView(CsrfExemptMixin, OAuth2Mixin, View):
    """
    """
    def post(self, request, *args, **kwargs):
        uri, http_method, body, headers = self._extract_params(request)

        url, headers, body, status = self.server.create_token_response(
            uri, http_method, body, headers)
        response = HttpResponse(content=body, status=status)

        for k, v in headers.items():
            response[k] = v
        return response


class ProtectedResourceMixin(OAuth2Mixin):
    """

    """
    def dispatch(self, request, *args, **kwargs):
        self.server = Server(OAuth2Validator(request.user))

        uri, http_method, body, headers = self._extract_params(request)

        # TODO: we need to pass a list of scopes requested by the protected resource
        valid, r = self.server.verify_request(uri, http_method, body, headers, scopes=None)
        if valid:
            return super(ProtectedResourceMixin, self).dispatch(request, *args, **kwargs)
        else:
            return HttpResponseForbidden()
