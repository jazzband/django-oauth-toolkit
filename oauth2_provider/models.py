from django.db import models
from django.conf import settings
from django.utils.translation import ugettext as _


class Application(models.Model):
    """
    An Application instance represents a Client on the Authorization server. Usually an Application is created manually
    by the Client developer after logging in on an Authorization Server.




    """
    CLIENT_CONFIDENTIAL = 'confidential'
    CLIENT_PUBLIC = 'public'
    CLIENT_TYPES = (
        (CLIENT_CONFIDENTIAL, _('Confidential')),
        (CLIENT_PUBLIC, _('Public')),
    )

    GRANT_ALLINONE = 'all-in-one'
    GRANT_AUTHORIZATION_CODE = 'authorization-code'
    GRANT_IMPLICIT = 'implicit'
    GRANT_PASSWORD = 'password'
    GRANT_CLIENT_CREDENTIAL = 'client-credential'
    GRANT_TYPES = (
        (GRANT_ALLINONE, _('All-in-one generic')),
        (GRANT_AUTHORIZATION_CODE, _('Authorization code')),
        (GRANT_IMPLICIT, _('Implicit')),
        (GRANT_PASSWORD, _('Resource owner password-based')),
        (GRANT_CLIENT_CREDENTIAL, _('Client credentials')),
    )

    client_id = models.CharField(max_length=100, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    default_redirect_uri = models.URLField(help_text=_("Your application's Redirection Endpoint"))  # default value (if not provided during auth. request)
    client_type = models.IntegerField(choices=CLIENT_TYPES)
    grant_type = models.IntegerField(choices=GRANT_TYPES)
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
    redirect_uri = models.CharField(max_length=255, blank=True)  # TODO remove blank and use Application's value at the time of the save?
    scope = models.TextField(blank=True)

    def __unicode__(self):
        return self.code


class AccessToken(models.Model):
    """

    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    token = models.CharField(max_length=255)  # TODO generate code
    client = models.ForeignKey(Application)
    expires = models.DateTimeField()  # TODO provide a default value based on the settings
    scope = models.TextField(blank=True)

    def __unicode__(self):
        return self.token


class RefreshToken(models.Model):
    """

    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    token = models.CharField(max_length=255)  # TODO generate code
    client = models.ForeignKey(Application)
    access_token = models.OneToOneField(AccessToken, related_name='refresh_token')

    def __unicode__(self):
        return self.token
