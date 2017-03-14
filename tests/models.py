from django.db import models

from oauth2_provider.models import AbstractApplication


class SampleApplication(AbstractApplication):
    custom_field = models.CharField(max_length=255)
