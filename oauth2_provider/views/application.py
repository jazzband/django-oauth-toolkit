from django.contrib.auth.mixins import LoginRequiredMixin
from django.forms.models import modelform_factory
from django.urls import reverse_lazy
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

    context_object_name = "application"
    template_name = "oauth2_provider/application_registration_form.html"
    success_template_name = "oauth2_provider/application_detail.html"

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
        if not form.cleaned_data["hash_client_secret"]:
            return super().form_valid(form)

        client_secret = form.instance.client_secret
        self.object = form.save()
        return self.response_class(
            request=self.request,
            template=self.success_template_name,
            context=self.get_context_data(
                client_secret=client_secret,
                show_client_secret_once=self.object.hash_client_secret,
                **{self.context_object_name: self.object},
            ),
            using=self.template_engine,
            content_type=self.content_type,
        )


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
