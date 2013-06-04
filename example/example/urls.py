from django.conf.urls import patterns, include, url
from django.views.generic import TemplateView
from django.contrib import admin
from .views import ConsumerView, ConsumerExchangeView

admin.autodiscover()

urlpatterns = patterns(
    '',
    url(r'^$', TemplateView.as_view(template_name='example/home.html'), name='home'),
    url(r'^exchange/', ConsumerExchangeView.as_view(), name='exchange'),
    url(r'^accounts/login/$', 'django.contrib.auth.views.login', {'template_name': 'example/login.html'}),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^o/', include('oauth2_provider.urls')),
    url(r'^consumer/$', ConsumerView.as_view(), name="consumer"),
)
