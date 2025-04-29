import logging

from django.contrib.auth.signals import user_logged_out
from django.dispatch import receiver

from .settings import oauth2_settings


logger = logging.getLogger(__name__)


@receiver(user_logged_out)
def on_user_logged_out_maybe_send_backchannel_logout(sender, **kwargs):
    handler = oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_HANDLER
    if not oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED or not callable(handler):
        return

    handler(user=kwargs["user"])
