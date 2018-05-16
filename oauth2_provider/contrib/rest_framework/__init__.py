# flake8: noqa
from .authentication import OAuth2Authentication
from .permissions import (
    TokenHasScope, TokenHasReadWriteScope, TokenMatchesOASRequirements,
    TokenHasResourceScope, IsAuthenticatedOrTokenHasScope
)
