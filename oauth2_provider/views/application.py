from django.core.urlresolvers import reverse_lazy
from django.views.generic import CreateView, DetailView, DeleteView, ListView, UpdateView

from braces.views import LoginRequiredMixin

from ..forms import RegistrationForm
from ..models import get_application_model


class ApplicationOwnerIsUserMixin(LoginRequiredMixin):
    """
    This mixin is used to provide an Application queryset filtered by the current request.user.
    """
    fields = '__all__'

    def get_queryset(self):
        return get_application_model().objects.filter(user=self.request.user)


class ApplicationRegistration(LoginRequiredMixin, CreateView):
    """
    View used to register a new Application for the request.user
    """
    form_class = RegistrationForm
    template_name = "oauth2_provider/application_registration_form.html"

    def form_valid(self, form):
        form.instance.user = self.request.user
        return super(ApplicationRegistration, self).form_valid(form)


class ApplicationDetail(ApplicationOwnerIsUserMixin, DetailView):
    """
    Detail view for an application instance owned by the request.user
    """
    context_object_name = 'application'
    template_name = "oauth2_provider/application_detail.html"


class ApplicationList(ApplicationOwnerIsUserMixin, ListView):
    """
    List view for all the applications owned by the request.user
    """
    context_object_name = 'applications'
    template_name = "oauth2_provider/application_list.html"


class ApplicationDelete(ApplicationOwnerIsUserMixin, DeleteView):
    """
    View used to delete an application owned by the request.user
    """
    context_object_name = 'application'
    success_url = reverse_lazy('oauth2_provider:list')
    template_name = "oauth2_provider/application_confirm_delete.html"


class ApplicationUpdate(ApplicationOwnerIsUserMixin, UpdateView):
    """
    View used to update an application owned by the request.user
    """
    context_object_name = 'application'
    template_name = "oauth2_provider/application_form.html"
