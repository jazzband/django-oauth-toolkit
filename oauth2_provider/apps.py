from django.apps import AppConfig


class OAuth2ProviderConfig(AppConfig):
    name = 'oauth2_provider'
    verbose_name = "OAuth2 provider"

    def ready(self):
        # Monkey-patch Meta.model and other root objects
        from .models import get_application_model
        Application = get_application_model()

        # monkey-patch views/application.ApplicationOwnerIsUserMixin model
        from .views.application import ApplicationOwnerIsUserMixin
        ApplicationOwnerIsUserMixin.model = Application

        # monkey-patch forms.RegistrationForm model
        from .forms import RegistrationForm
        RegistrationForm.Meta.model = Application

        # monkey-patch oauth2_validators.Appliacation and GRANT_TYPE_MAPPING
        from . import oauth2_validators
        oauth2_validators.Application = Application
        oauth2_validators.GRANT_TYPE_MAPPING = {
            'authorization_code': (Application.GRANT_AUTHORIZATION_CODE,),
            'password': (Application.GRANT_PASSWORD,),
            'client_credentials': (Application.GRANT_CLIENT_CREDENTIALS,),
            'refresh_token': (Application.GRANT_AUTHORIZATION_CODE, Application.GRANT_PASSWORD,
                              Application.GRANT_CLIENT_CREDENTIALS)
        }
