from django.db import models
from oauth2_provider.compat import AUTH_USER_MODEL
from oauth2_provider.models import (AbstractAccessToken, AbstractApplication,
                                    AbstractGrant)
from oauth2_provider.settings import oauth2_settings


class TestApplication(AbstractApplication):
    custom_field = models.CharField(max_length=255)

class TestGrant(AbstractGrant):
    custom_field = models.CharField(max_length=255)

class TestAccessToken(AbstractAccessToken):
    custom_field = models.CharField(max_length=255)

class TestRefreshToken(models.Model):
    user = models.ForeignKey(AUTH_USER_MODEL)
    token = models.CharField(max_length=255, db_index=True)
    application = models.ForeignKey(oauth2_settings.APPLICATION_MODEL)
    access_token = models.OneToOneField(oauth2_settings.ACCESS_TOKEN_MODEL,
                                        related_name='test_refresh_token')

    def revoke(self):
        """
        Delete this refresh token along with related access token
        """
        AccessToken.objects.get(id=self.access_token.id).revoke()
        self.delete()

    def __str__(self):
        return self.token
