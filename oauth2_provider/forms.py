from django import forms


class AllowForm(forms.Form):
    allow = forms.BooleanField(required=False)
    redirect_uri = forms.CharField(widget=forms.HiddenInput())
    scope = forms.CharField(widget=forms.HiddenInput())
    client_id = forms.CharField(widget=forms.HiddenInput())
    state = forms.CharField(required=False, widget=forms.HiddenInput())
    response_type = forms.CharField(widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        data = kwargs.get('data')
        # backwards compatible support for plural `scopes` query parameter
        if data and 'scopes' in data:
            data['scope'] = data['scopes']
        return super(AllowForm, self).__init__(*args, **kwargs)
