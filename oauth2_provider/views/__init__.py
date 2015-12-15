# flake8: noqa
from .base import AuthorizationView, TokenView, RevokeTokenView
from .application import ApplicationRegistration, ApplicationDetail, ApplicationList, \
    ApplicationDelete, ApplicationUpdate
from .generic import ProtectedResourceView, ScopedProtectedResourceView, ReadWriteScopedResourceView
from .token import AuthorizedTokensListView, AuthorizedTokenDeleteView
