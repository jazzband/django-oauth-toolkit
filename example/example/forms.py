from django import forms


class ConsumerForm(forms.Form):
    client_id = forms.CharField()
    authorization_url = forms.URLField()


class ConsumerExchangeForm(forms.Form):
    code = forms.CharField(widget=forms.TextInput(attrs={'readonly':'readonly'}))
    state = forms.CharField(widget=forms.TextInput(attrs={'readonly':'readonly'}))
    token_url = forms.URLField()
    grant_type = forms.CharField(widget=forms.HiddenInput(), initial='authorization_code')
    redirect_url = forms.CharField()
    client_id = forms.CharField()
    client_secret = forms.CharField()
