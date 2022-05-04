from django.contrib import admin
from django.urls import include, path

from .views import MockView


admin.autodiscover()


urlpatterns = [
    path("o/", include("oauth2_provider.urls", namespace="oauth2_provider")),
    path("admin/", admin.site.urls),
    path("cors-test/", MockView.as_view()),
]
