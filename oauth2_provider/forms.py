from django import forms


class AllowForm(forms.Form):
    allow = forms.BooleanField()
    redirect_uri = forms.URLField(widget=forms.HiddenInput())
    scopes = forms.CharField(widget=forms.HiddenInput())
    client_id = forms.CharField(widget=forms.HiddenInput())
    state = forms.CharField(widget=forms.HiddenInput())
