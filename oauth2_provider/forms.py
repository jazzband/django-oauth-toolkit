from django import forms


class AllowForm(forms.Form):
    redirect_uri = forms.URLField(widget=forms.HiddenInput())
    scopes = forms.CharField(required=False, widget=forms.HiddenInput())
    client_id = forms.CharField(widget=forms.HiddenInput())
    state = forms.CharField(required=False, widget=forms.HiddenInput())
    user_id = forms.IntegerField(required=True, widget=forms.HiddenInput())
