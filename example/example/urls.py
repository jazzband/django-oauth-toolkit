from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.core.urlresolvers import reverse_lazy
from django.views.generic import TemplateView
from oauth2_provider import VERSION

from .views import ConsumerView, ConsumerExchangeView, ConsumerDoneView, ApiEndpoint

admin.autodiscover()

urlpatterns = patterns(
    '',
    url(r'^$', TemplateView.as_view(template_name='example/home.html'), {'version': VERSION}, name='home'),
    url(r'^accounts/login/$', 'django.contrib.auth.views.login', {'template_name': 'example/login.html'}),
    url(r'^accounts/logout/$', 'django.contrib.auth.views.logout', {'next_page': reverse_lazy('home')}),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^consumer/$', ConsumerView.as_view(), name="consumer"),
    url(r'^consumer/exchange/', ConsumerExchangeView.as_view(), name='consumer-exchange'),
    url(r'^consumer/done/', ConsumerDoneView.as_view(), name='consumer-done'),
    url(r'^consumer/client/', TemplateView.as_view(template_name='example/consumer-client.html'), name='consumer-client'),
    url(r'^o/', include('oauth2_provider.urls')),
    url(r'^api/hello', ApiEndpoint.as_view()),
)
