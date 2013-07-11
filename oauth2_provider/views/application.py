from django.core.urlresolvers import reverse_lazy
from django.views.generic import CreateView, DetailView, DeleteView, ListView, UpdateView

from braces.views import LoginRequiredMixin

from ..forms import RegistrationForm
from ..models import Application


class ApplicationOwnerIsUserMixin(LoginRequiredMixin):
    """
    TODO: add docstring
    """
    model = Application

    def get_queryset(self):
        queryset = super(ApplicationOwnerIsUserMixin, self).get_queryset()
        return queryset.filter(user=self.request.user)


class ApplicationRegistration(LoginRequiredMixin, CreateView):
    """
    TODO: add docstring
    """
    form_class = RegistrationForm
    template_name = "oauth2_provider/application_registration_form.html"

    def form_valid(self, form):
        form.instance.user = self.request.user
        return super(ApplicationRegistration, self).form_valid(form)


class ApplicationDetail(ApplicationOwnerIsUserMixin, DetailView):
    """
    TODO: add docstring
    """
    context_object_name = 'application'


class ApplicationList(ApplicationOwnerIsUserMixin, ListView):
    """
    TODO: add docstring
    """
    context_object_name = 'applications'


class ApplicationDelete(ApplicationOwnerIsUserMixin, DeleteView):
    """
    TODO: add docstring
    """
    context_object_name = 'application'
    success_url = reverse_lazy('oauth2_provider:list')


class ApplicationUpdate(ApplicationOwnerIsUserMixin, UpdateView):
    """
    TODO: add docstring
    """
    context_object_name = 'application'
