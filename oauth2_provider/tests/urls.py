import django
from django.conf.urls import include, url
from django.contrib import admin

admin.autodiscover()


urlpatterns = [
    url(r'^o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
]


if django.VERSION < (1, 9, 0):
    urlpatterns += [url(r"^admin/", include(admin.site.urls))]
else:
    urlpatterns += [url(r"^admin/", admin.site.urls)]
