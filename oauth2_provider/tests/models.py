from django.conf import settings
from django.db import models
from oauth2_provider.models import AbstractApplication


class TestApplication(AbstractApplication):
    custom_field = models.CharField(max_length=255)

class TestResourceOwner(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="resource_owners")
