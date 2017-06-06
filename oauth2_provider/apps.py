from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class DOTConfig(AppConfig):
    name = "oauth2_provider"
    verbose_name = _("Django OAuth Toolkit")
