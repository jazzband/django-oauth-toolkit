from django import forms


class ConsumerForm(forms.Form):
    client_id = forms.CharField()
    authorization_url = forms.URLField()