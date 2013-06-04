from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.core.urlresolvers import reverse_lazy
from django.views.generic import TemplateView

from .views import ConsumerView, ConsumerExchangeView

admin.autodiscover()

urlpatterns = patterns(
    '',
    url(r'^$', TemplateView.as_view(template_name='example/home.html'), name='home'),
    url(r'^consumer/exchange/', ConsumerExchangeView.as_view(), name='exchange'),
    url(r'^accounts/login/$', 'django.contrib.auth.views.login', {'template_name': 'example/login.html'}),
    url(r'^accounts/logout/$', 'django.contrib.auth.views.logout', {'next_page': reverse_lazy('home')}),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^o/', include('oauth2_provider.urls')),
    url(r'^consumer/$', ConsumerView.as_view(), name="consumer"),
)
