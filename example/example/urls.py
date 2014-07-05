from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.core.urlresolvers import reverse_lazy
from django.views.generic import TemplateView

from .views import (
    ConsumerView, ConsumerExchangeView, ConsumerDoneView, ApiEndpoint, ApiClientView
)
from .api_v1 import get_system_info, applications_list, applications_detail

admin.autodiscover()

urlpatterns = patterns(
    '',
    url(
        regex=r'^$',
        view=TemplateView.as_view(template_name='example/home.html'),
        name='home'
    ),
    url(
        regex=r'^accounts/login/$',
        view='django.contrib.auth.views.login',
        kwargs={'template_name': 'example/login.html'}
    ),
    url(
        regex='^accounts/logout/$',
        view='django.contrib.auth.views.logout',
        kwargs={'next_page': reverse_lazy('home')}
    ),

    # the Django admin
    url(r'^admin/', include(admin.site.urls)),

    # consumer logic
    url(
        regex=r'^consumer/$',
        view=ConsumerView.as_view(),
        name="consumer"
    ),
    url(
        regex=r'^consumer/exchange/',
        view=ConsumerExchangeView.as_view(),
        name='consumer-exchange'
    ),
    url(
        regex=r'^consumer/done/',
        view=ConsumerDoneView.as_view(),
        name='consumer-done'
    ),
    url(
        regex=r'^consumer/client/',
        view=TemplateView.as_view(template_name='example/consumer-client.html'),
        name='consumer-client'
    ),

    # oauth2 urls
    url(r'^o/', include('oauth2_provider.urls', namespace='oauth2_provider')),

    # api stuff to test server functionalities
    url(r'^apiclient$', ApiClientView.as_view(), name='api-client'),
    url(r'^api/hello$', ApiEndpoint.as_view(), name='Hello'),

    # api v1
    url(r'^api/v1/system_info$', get_system_info, name="System Info"),
    url(r'^api/v1/applications$', applications_list, name="Application List"),
    url(r'^api/v1/applications/(?P<lookup>\w+)/$', applications_detail, name="Application Detail"),
)
