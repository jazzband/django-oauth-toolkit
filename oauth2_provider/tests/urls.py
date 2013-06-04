from django.conf.urls import patterns, include, url


urlpatterns = patterns(
    '',
    url(r'^o/', include('oauth2_provider.urls')),
)
