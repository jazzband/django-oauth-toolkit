from django.db import models

from oauth2_provider.models import (
    AbstractAccessToken, AbstractApplication,
    AbstractGrant, AbstractRefreshToken
)


class SampleApplication(AbstractApplication):
    custom_field = models.CharField(max_length=255)


class SampleAccessToken(AbstractAccessToken):
    custom_field = models.CharField(max_length=255)


class SampleRefreshToken(AbstractRefreshToken):
    custom_field = models.CharField(max_length=255)


class SampleGrant(AbstractGrant):
    custom_field = models.CharField(max_length=255)
