from django.db import models
from django.conf import settings
from django.utils.translation import ugettext as _


class Application(models.Model):
    """


    """
    CLIENT_CONFIDENTIAL = 'confidential'
    CLIENT_PUBLIC = 'public'
    CLIENT_TYPES = (
        (CLIENT_CONFIDENTIAL, _('Confidential')),
        (CLIENT_PUBLIC, _('Public')),
    )

    client_id = models.CharField(max_length=100, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    default_redirect_uri = models.URLField(help_text=_("Your application's Redirection Endpoint"))  # default value (if not provided during auth. request)
    client_type = models.IntegerField(choices=CLIENT_TYPES)
    client_secret = models.CharField(max_length=255)  # TODO generate code
    name = models.CharField(max_length=255, blank=True)

    def __unicode__(self):
        return self.client_id


class Grant(models.Model):
    """

    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    code = models.CharField(max_length=255)  # TODO generate code
    client = models.ForeignKey(Application)
    expires = models.DateTimeField()  # TODO generate short expire time
    redirect_uri = models.CharField(max_length=255, blank=True)  # TODO remove blank and use Client's value at the time of the save?
    scope = models.TextField(blank=True)

    def __unicode__(self):
        return self.code


class AccessToken(models.Model):
    """

    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    token = models.CharField(max_length=255)  # TODO generate code
    client = models.ForeignKey(Client)
    expires = models.DateTimeField()  # TODO provide a default value based on the settings
    scope = models.TextField(blank=True)

    def __unicode__(self):
        return self.token


class RefreshToken(models.Model):
    """

    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    token = models.CharField(max_length=255)  # TODO generate code
    client = models.ForeignKey(Client)
    access_token = models.OneToOneField(AccessToken, related_name='refresh_token')

    def __unicode__(self):
        return self.token
