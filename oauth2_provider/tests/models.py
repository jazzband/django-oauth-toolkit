from django.db import models
from oauth2_provider.models import (AbstractApplication,
                                    AbstractGrant,
                                    AbstractAccessToken,
                                    AbstractRefreshToken)


class TestApplication(AbstractApplication):
    custom_field = models.CharField(max_length=255)

class TestGrant(AbstractGrant):
    custom_field = models.CharField(max_length=255)

class TestAccessToken(AbstractAccessToken):
    custom_field = models.CharField(max_length=255)

class TestRefreshToken(AbstractRefreshToken):
    custom_field = models.CharField(max_length=255)
