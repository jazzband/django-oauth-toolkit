import calendar

from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from oauth2_provider.models import get_access_token_model
from oauth2_provider.views.generic import ClientProtectedScopedResourceView


@method_decorator(csrf_exempt, name="dispatch")
class IntrospectTokenView(ClientProtectedScopedResourceView):
    """
    Implements an endpoint for token introspection based
    on RFC 7662 https://tools.ietf.org/html/rfc7662

    To access this view the request must pass a OAuth2 Bearer Token
    which is allowed to access the scope `introspection`.
    """

    required_scopes = ["introspection"]

    @staticmethod
    def get_token_response(token_value=None):
        try:
            token = (
                get_access_token_model().objects.select_related("user", "application").get(token=token_value)
            )
        except ObjectDoesNotExist:
            return JsonResponse({"active": False}, status=200)
        else:
            if token.is_valid():
                data = {
                    "active": True,
                    "scope": token.scope,
                    "exp": int(calendar.timegm(token.expires.timetuple())),
                }
                if token.application:
                    data["client_id"] = token.application.client_id
                if token.user:
                    data["username"] = token.user.get_username()
                return JsonResponse(data)
            else:
                return JsonResponse({"active": False}, status=200)

    def get(self, request, *args, **kwargs):
        """
        Get the token from the URL parameters.
        URL: https://example.com/introspect?token=mF_9.B5f-4.1JqM

        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        return self.get_token_response(request.GET.get("token", None))

    def post(self, request, *args, **kwargs):
        """
        Get the token from the body form parameters.
        Body: token=mF_9.B5f-4.1JqM

        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        return self.get_token_response(request.POST.get("token", None))
