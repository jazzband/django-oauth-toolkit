from django.conf.urls import patterns, include, url
from django.views.generic import TemplateView
from django.contrib import admin
from .views import ConsumerView, ConsumerLinkView

admin.autodiscover()

urlpatterns = patterns(
    '',
    url(r'^$', 'example.views.home', name='home'),
    url(r'^exchange/', 'example.views.exchange', name='exchange'),
    url(r'^accounts/login/$', 'django.contrib.auth.views.login', {'template_name': 'example/login.html'}),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^o/', include('oauth2_provider.urls')),
    url(r'^consumer/$', ConsumerView.as_view(), name="consumer"),
    url(r'^consumer/auth-link', ConsumerLinkView.as_view(), name=""),
)
