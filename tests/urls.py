from django.contrib import admin
from django.urls import include, path


admin.autodiscover()


urlpatterns = [
    path("o/", include("oauth2_provider.urls", namespace="oauth2_provider")),
    path("admin/", admin.site.urls),
]
