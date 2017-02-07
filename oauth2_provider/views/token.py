from __future__ import absolute_import, unicode_literals

from django.views.generic import ListView, DeleteView
from braces.views import LoginRequiredMixin

from ..compat import reverse_lazy
from ..models import AccessToken


class AuthorizedTokensListView(LoginRequiredMixin, ListView):
    """
    Show a page where the current logged-in user can see his tokens so they can revoke them
    """
    context_object_name = 'authorized_tokens'
    template_name = 'oauth2_provider/authorized-tokens.html'
    model = AccessToken

    def get_queryset(self):
        """
        Show only user's tokens
        """
        return super(AuthorizedTokensListView, self).get_queryset()\
            .select_related('application').filter(user=self.request.user)


class AuthorizedTokenDeleteView(LoginRequiredMixin, DeleteView):
    """
    View for revoking a specific token
    """
    template_name = 'oauth2_provider/authorized-token-delete.html'
    success_url = reverse_lazy('oauth2_provider:authorized-token-list')
    model = AccessToken

    def get_queryset(self):
        return super(AuthorizedTokenDeleteView, self).get_queryset().filter(user=self.request.user)
