import logging

from django.contrib.auth.signals import user_logged_out
from django.dispatch import receiver

from .exceptions import BackchannelLogoutRequestError
from .settings import oauth2_settings
from .models import get_logout_token_model, get_application_model, get_access_token_model


logger = logging.getLogger(__name__)

LogoutToken = get_logout_token_model()
Application = get_application_model()
AccessToken = get_access_token_model()


@receiver(user_logged_out)
def on_user_logged_out_maybe_send_backchannel_logout(sender, **kw):
    if not oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED:
        return

    request = kw["request"]
    user = kw["user"]

    applications = Application.objects.exclude(backchannel_logout_uri__isnull=True)
    for application in applications:
        logout_token = LogoutToken.objects.create(
            user=user, session_key=request.session.session_key, application=application
        )
        try:
            logout_token.send_backchannel_logout_request()
        except BackchannelLogoutRequestError as exc:
            logger.warn(str(exc))
