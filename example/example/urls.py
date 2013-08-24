from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.core.urlresolvers import reverse_lazy
from django.views.generic import TemplateView
from oauth2_provider import VERSION

from .views import (
    ConsumerView, ConsumerExchangeView, ConsumerDoneView, ApiEndpoint, ApiClientView, ApiResolve
)
from .api_v1 import get_system_info, applications_list

admin.autodiscover()

urlpatterns = patterns(
    '',
    url(r'^$', TemplateView.as_view(template_name='example/home.html'),
        {'version': VERSION}, name='home'),
    url(r'^accounts/login/$', 'django.contrib.auth.views.login',
        {'template_name': 'example/login.html'}),
    url(r'^accounts/logout/$', 'django.contrib.auth.views.logout',
        {'next_page': reverse_lazy('home')}),
    url(r'^admin/', include(admin.site.urls)),

    # consumer logic
    url(r'^consumer/$', ConsumerView.as_view(), name="consumer"),
    url(r'^consumer/exchange/', ConsumerExchangeView.as_view(), name='consumer-exchange'),
    url(r'^consumer/done/', ConsumerDoneView.as_view(), name='consumer-done'),
    url(r'^consumer/client/', TemplateView.as_view(template_name='example/consumer-client.html'),
        name='consumer-client'),

    # oauth2 urls
    url(r'^o/', include('oauth2_provider.urls', namespace='oauth2_provider')),

    # api stuff to test server functionalities
    url(r'^apiclient$', ApiClientView.as_view(), name='api-client'),
    url(r'^resolve$', ApiResolve.as_view(), name='resolve'),

    url(r'^api/hello$', ApiEndpoint.as_view(), name='Hello'),

    # api v1
    url(r'^api/v1/system_info$', get_system_info, name="System Info"),
    url(r'^api/v1/applications$', applications_list, name="Application List"),
    url(r'^api/v1/applications/(?P<pk>\w+)/$', get_system_info, name="Application Detail"),
)
