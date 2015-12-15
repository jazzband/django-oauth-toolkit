from .base import AuthorizationView, TokenView, RevokeTokenView  # noqa
from .application import ApplicationRegistration, ApplicationDetail, ApplicationList, ApplicationDelete, ApplicationUpdate  # noqa
from .generic import ProtectedResourceView, ScopedProtectedResourceView, ReadWriteScopedResourceView  # noqa
from .token import AuthorizedTokensListView, AuthorizedTokenDeleteView  # noqa
