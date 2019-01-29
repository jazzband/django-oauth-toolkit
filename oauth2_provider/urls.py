from django.conf.urls import url

from . import views


app_name = "oauth2_provider"


base_urlpatterns = [
    url(r"^authorize/$", views.AuthorizationView.as_view(), name="authorize"),
    url(r"^token/$", views.TokenView.as_view(), name="token"),
    url(r"^revoke_token/$", views.RevokeTokenView.as_view(), name="revoke-token"),
    url(r"^introspect/$", views.IntrospectTokenView.as_view(), name="introspect"),
]


management_urlpatterns = [
    # Application management views
    url(r"^applications/$", views.ApplicationList.as_view(), name="list"),
    url(r"^applications/register/$", views.ApplicationRegistration.as_view(), name="register"),
    url(r"^applications/(?P<pk>[\w-]+)/$", views.ApplicationDetail.as_view(), name="detail"),
    url(r"^applications/(?P<pk>[\w-]+)/delete/$", views.ApplicationDelete.as_view(), name="delete"),
    url(r"^applications/(?P<pk>[\w-]+)/update/$", views.ApplicationUpdate.as_view(), name="update"),
    # Token management views
    url(r"^authorized_tokens/$", views.AuthorizedTokensListView.as_view(), name="authorized-token-list"),
    url(r"^authorized_tokens/(?P<pk>[\w-]+)/delete/$", views.AuthorizedTokenDeleteView.as_view(),
        name="authorized-token-delete"),
]

oidc_urlpatterns = [
    url(r"^\.well-known/openid-configuration/$", views.ConnectDiscoveryInfoView.as_view(), name="oidc-connect-discovery-info"),
    url(r"^jwks/$", views.JwksInfoView.as_view(), name="jwks-info"),
    url(r"^userinfo/$", views.UserInfoView.as_view(), name="user-info")
]


urlpatterns = base_urlpatterns + management_urlpatterns + oidc_urlpatterns
