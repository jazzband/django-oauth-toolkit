from __future__ import absolute_import
from django.conf.urls import patterns, url

from . import views

urlpatterns = patterns(
    '',
    url(r'^authorize/$', views.AuthorizationView.as_view(), name="authorize"),
    url(r'^token/$', views.TokenView.as_view(), name="token"),
)
