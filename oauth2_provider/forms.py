from django import forms


class AllowForm(forms.Form):
    allow = forms.BooleanField()
