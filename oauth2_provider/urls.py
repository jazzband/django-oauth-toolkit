from __future__ import absolute_import
from django.conf.urls import patterns, url

from . import views

urlpatterns = patterns(
    '',
    url(r'^authorize/$', views.AuthorizationCodeView.as_view(), name="authorize"),
)
