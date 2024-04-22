from corsheaders.signals import check_request_enabled
from django.apps import AppConfig


def cors_allow_origin(sender, request, **kwargs):
    return (
        request.path == "/o/userinfo/"
        or request.path == "/o/userinfo"
        or request.path == "/o/.well-known/openid-configuration"
        or request.path == "/o/.well-known/openid-configuration/"
    )


class IDPAppConfig(AppConfig):
    name = "idp"
    default = True

    def ready(self):
        check_request_enabled.connect(cors_allow_origin)
