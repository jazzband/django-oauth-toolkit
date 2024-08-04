from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.forms.models import modelform_factory
from django.urls import reverse_lazy
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView

from ..models import get_application_model


class ApplicationOwnerIsUserMixin(LoginRequiredMixin):
    """
    This mixin is used to provide an Application queryset filtered by the current request.user.
    """

    fields = "__all__"

    def get_queryset(self):
        return get_application_model().objects.filter(user=self.request.user)


class ApplicationRegistration(LoginRequiredMixin, CreateView):
    """
    View used to register a new Application for the request.user
    """

    template_name = "oauth2_provider/application_registration_form.html"

    def get_form_class(self):
        """
        Returns the form class for the application model
        """
        return modelform_factory(
            get_application_model(),
            fields=(
                "name",
                "hash_client_secret",
                "client_type",
                "authorization_grant_type",
                "redirect_uris",
                "post_logout_redirect_uris",
                "allowed_origins",
                "algorithm",
            ),
        )

    def form_valid(self, form):
        form.instance.user = self.request.user
        # If we are hashing the client secret, display the cleartext value in a flash message with
        # Django's messages framework
        if form.cleaned_data["hash_client_secret"]:
            messages.add_message(
                self.request,
                messages.SUCCESS,
                # Since the client_secret is not user-supplied, we can manually mark this entire
                # string as safe so Django doesn't re-encode the HTML markup
                mark_safe(
                    _(
                        "The application client secret is:<br /><code>%s</code><br />"
                        "This will only be shown once, so copy it now!"
                    )
                    % form.instance.client_secret
                ),
            )
        return super().form_valid(form)


class ApplicationDetail(ApplicationOwnerIsUserMixin, DetailView):
    """
    Detail view for an application instance owned by the request.user
    """

    context_object_name = "application"
    template_name = "oauth2_provider/application_detail.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        if not ctx["application"].hash_client_secret:
            ctx["client_secret"] = ctx["application"].client_secret
        return ctx


class ApplicationList(ApplicationOwnerIsUserMixin, ListView):
    """
    List view for all the applications owned by the request.user
    """

    context_object_name = "applications"
    template_name = "oauth2_provider/application_list.html"


class ApplicationDelete(ApplicationOwnerIsUserMixin, DeleteView):
    """
    View used to delete an application owned by the request.user
    """

    context_object_name = "application"
    success_url = reverse_lazy("oauth2_provider:list")
    template_name = "oauth2_provider/application_confirm_delete.html"


class ApplicationUpdate(ApplicationOwnerIsUserMixin, UpdateView):
    """
    View used to update an application owned by the request.user
    """

    context_object_name = "application"
    template_name = "oauth2_provider/application_form.html"

    def get_form_class(self):
        """
        Returns the form class for the application model
        """
        return modelform_factory(
            get_application_model(),
            fields=(
                "name",
                "client_type",
                "authorization_grant_type",
                "redirect_uris",
                "post_logout_redirect_uris",
                "allowed_origins",
                "algorithm",
            ),
        )
