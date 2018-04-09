from django.db import models

from oauth2_provider.models import (
    AbstractAccessToken, AbstractApplication,
    AbstractGrant, AbstractRefreshToken
)


class BaseTestApplication(AbstractApplication):
    allowed_schemes = models.TextField(blank=True)

    def get_allowed_schemes(self):
        if self.allowed_schemes:
            return self.allowed_schemes.split()
        return super(BaseTestApplication, self).get_allowed_schemes()


class SampleApplication(AbstractApplication):
    custom_field = models.CharField(max_length=255)


class SampleAccessToken(AbstractAccessToken):
    custom_field = models.CharField(max_length=255)


class SampleRefreshToken(AbstractRefreshToken):
    custom_field = models.CharField(max_length=255)


class SampleGrant(AbstractGrant):
    custom_field = models.CharField(max_length=255)
