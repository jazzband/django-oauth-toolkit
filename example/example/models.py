from oauth2_provider.models import AbstractApplication

from django.db import models


class MyApplication(AbstractApplication):
    """
    Custom Application model which adds description field
    """
    description = models.TextField()
