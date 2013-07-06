from django import forms

from .models import Application


class AllowForm(forms.Form):
    allow = forms.BooleanField(required=False)
    redirect_uri = forms.CharField(widget=forms.HiddenInput())
    scopes = forms.CharField(required=False, widget=forms.HiddenInput())
    client_id = forms.CharField(widget=forms.HiddenInput())
    state = forms.CharField(required=False, widget=forms.HiddenInput())
    response_type = forms.CharField(widget=forms.HiddenInput())


class RegistrationForm(forms.ModelForm):
    """
    TODO: add docstring
    """
    class Meta:
        model = Application
