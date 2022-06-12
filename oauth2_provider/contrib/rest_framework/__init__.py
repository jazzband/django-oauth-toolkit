# flake8: noqa
from .authentication import OAuth2Authentication
from .decorators import required_scopes
from .permissions import (
    IsAuthenticatedOrTokenHasScope,
    TokenHasReadWriteScope,
    TokenHasResourceScope,
    TokenHasScope,
    TokenMatchesOASRequirements,
)
