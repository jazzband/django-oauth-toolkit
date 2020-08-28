from django.contrib import admin
from django.urls import include, re_path


admin.autodiscover()


urlpatterns = [
    re_path(r"^o/", include("oauth2_provider.urls", namespace="oauth2_provider")),
    re_path(r"^admin/", admin.site.urls),
]
