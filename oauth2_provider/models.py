from __future__ import unicode_literals

from datetime import timedelta

from django.core.urlresolvers import reverse
from django.db import models, transaction
from django.utils import timezone

from django.utils.translation import ugettext_lazy as _
from django.utils.encoding import python_2_unicode_compatible
from django.core.exceptions import ImproperlyConfigured

from .settings import oauth2_settings
from .compat import AUTH_USER_MODEL, parse_qsl, urlparse, get_model
from .generators import generate_client_secret, generate_client_id
from .validators import validate_uris


@python_2_unicode_compatible
class AbstractApplication(models.Model):
    """
    An Application instance represents a Client on the Authorization server.
    Usually an Application is created manually by client's developers after
    logging in on an Authorization Server.

    Fields:

    * :attr:`client_id` The client identifier issued to the client during the
                        registration process as described in :rfc:`2.2`
    * :attr:`user` ref to a Django user
    * :attr:`redirect_uris` The list of allowed redirect uri. The string
                            consists of valid URLs separated by space
    * :attr:`client_type` Client type as described in :rfc:`2.1`
    * :attr:`authorization_grant_type` Authorization flows available to the
                                       Application
    * :attr:`client_secret` Confidential secret issued to the client during
                            the registration process as described in :rfc:`2.2`
    * :attr:`name` Friendly name for the Application
    """
    CLIENT_CONFIDENTIAL = 'confidential'
    CLIENT_PUBLIC = 'public'
    CLIENT_TYPES = (
        (CLIENT_CONFIDENTIAL, _('Confidential')),
        (CLIENT_PUBLIC, _('Public')),
    )

    GRANT_AUTHORIZATION_CODE = 'authorization-code'
    GRANT_IMPLICIT = 'implicit'
    GRANT_PASSWORD = 'password'
    GRANT_CLIENT_CREDENTIALS = 'client-credentials'
    GRANT_TYPES = (
        (GRANT_AUTHORIZATION_CODE, _('Authorization code')),
        (GRANT_IMPLICIT, _('Implicit')),
        (GRANT_PASSWORD, _('Resource owner password-based')),
        (GRANT_CLIENT_CREDENTIALS, _('Client credentials')),
    )

    client_id = models.CharField(max_length=100, unique=True,
                                 default=generate_client_id, db_index=True)
    user = models.ForeignKey(AUTH_USER_MODEL, related_name="%(app_label)s_%(class)s")
    help_text = _("Allowed URIs list, space separated")
    redirect_uris = models.TextField(help_text=help_text,
                                     validators=[validate_uris], blank=True)
    client_type = models.CharField(max_length=32, choices=CLIENT_TYPES)
    authorization_grant_type = models.CharField(max_length=32,
                                                choices=GRANT_TYPES)
    client_secret = models.CharField(max_length=255, blank=True,
                                     default=generate_client_secret, db_index=True)
    name = models.CharField(max_length=255, blank=True)
    skip_authorization = models.BooleanField(default=False)

    class Meta:
        abstract = True

    @property
    def default_redirect_uri(self):
        """
        Returns the default redirect_uri extracting the first item from
        the :attr:`redirect_uris` string
        """
        if self.redirect_uris:
            return self.redirect_uris.split().pop(0)

        assert False, "If you are using implicit, authorization_code" \
                      "or all-in-one grant_type, you must define " \
                      "redirect_uris field in your Application model"

    def redirect_uri_allowed(self, uri):
        """
        Checks if given url is one of the items in :attr:`redirect_uris` string

        :param uri: Url to check
        """
        for allowed_uri in self.redirect_uris.split():
            parsed_allowed_uri = urlparse(allowed_uri)
            parsed_uri = urlparse(uri)

            if (parsed_allowed_uri.scheme == parsed_uri.scheme and
                    parsed_allowed_uri.netloc == parsed_uri.netloc and
                    parsed_allowed_uri.path == parsed_uri.path):

                aqs_set = set(parse_qsl(parsed_allowed_uri.query))
                uqs_set = set(parse_qsl(parsed_uri.query))

                if aqs_set.issubset(uqs_set):
                    return True

        return False

    def clean(self):
        from django.core.exceptions import ValidationError
        if not self.redirect_uris \
            and self.authorization_grant_type \
            in (AbstractApplication.GRANT_AUTHORIZATION_CODE,
                AbstractApplication.GRANT_IMPLICIT):
            error = _('Redirect_uris could not be empty with {0} grant_type')
            raise ValidationError(error.format(self.authorization_grant_type))

    def get_absolute_url(self):
        return reverse('oauth2_provider:detail', args=[str(self.id)])

    def __str__(self):
        return self.name or self.client_id


class Application(AbstractApplication):
    pass

# Add swappable like this to not break django 1.4 compatibility
Application._meta.swappable = 'OAUTH2_PROVIDER_APPLICATION_MODEL'


@python_2_unicode_compatible
class Grant(models.Model):
    """
    A Grant instance represents a token with a short lifetime that can
    be swapped for an access token, as described in :rfc:`4.1.2`

    Fields:

    * :attr:`user` The Django user who requested the grant
    * :attr:`code` The authorization code generated by the authorization server
    * :attr:`application` Application instance this grant was asked for
    * :attr:`expires` Expire time in seconds, defaults to
                      :data:`settings.AUTHORIZATION_CODE_EXPIRE_SECONDS`
    * :attr:`redirect_uri` Self explained
    * :attr:`scope` Required scopes, optional
    """
    user = models.ForeignKey(AUTH_USER_MODEL)
    code = models.CharField(max_length=255, db_index=True)  # code comes from oauthlib
    application = models.ForeignKey(oauth2_settings.APPLICATION_MODEL)
    expires = models.DateTimeField()
    redirect_uri = models.CharField(max_length=255)
    scope = models.TextField(blank=True)

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def redirect_uri_allowed(self, uri):
        return uri == self.redirect_uri

    def __str__(self):
        return self.code


@python_2_unicode_compatible
class AccessToken(models.Model):
    """
    An AccessToken instance represents the actual access token to
    access user's resources, as in :rfc:`5`.

    Fields:

    * :attr:`user` The Django user representing resources' owner
    * :attr:`token` Access token
    * :attr:`application` Application instance
    * :attr:`expires` Date and time of token expiration, in DateTime format
    * :attr:`scope` Allowed scopes
    """
    user = models.ForeignKey(AUTH_USER_MODEL, blank=True, null=True)
    token = models.CharField(max_length=255, db_index=True)
    application = models.ForeignKey(oauth2_settings.APPLICATION_MODEL)
    expires = models.DateTimeField()
    scope = models.TextField(blank=True)

    def is_valid(self, scopes=None):
        """
        Checks if the access token is valid.

        :param scopes: An iterable containing the scopes to check or None
        """
        return not self.is_expired() and self.allow_scopes(scopes)

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def allow_scopes(self, scopes):
        """
        Check if the token allows the provided scopes

        :param scopes: An iterable containing the scopes to check
        """
        if not scopes:
            return True

        provided_scopes = set(self.scope.split())
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)

    def revoke(self):
        """
        Convenience method to uniform tokens' interface, for now
        simply remove this token from the database in order to revoke it.
        """
        self.delete()

    @property
    def scopes(self):
        """
        Returns a dictionary of allowed scope names (as keys) with their descriptions (as values)
        """
        return {name: desc for name, desc in oauth2_settings.SCOPES.items() if name in self.scope.split()}

    def __str__(self):
        return self.token


@python_2_unicode_compatible
class RefreshToken(models.Model):
    """
    A RefreshToken instance represents a token that can be swapped for a new
    access token when it expires.

    Fields:

    * :attr:`user` The Django user representing resources' owner
    * :attr:`token` Token value
    * :attr:`application` Application instance
    * :attr:`access_token` AccessToken instance this refresh token is
                           bounded to
    """
    user = models.ForeignKey(AUTH_USER_MODEL)
    token = models.CharField(max_length=255, db_index=True)
    application = models.ForeignKey(oauth2_settings.APPLICATION_MODEL)
    access_token = models.OneToOneField(AccessToken,
                                        related_name='refresh_token')

    def revoke(self):
        """
        Delete this refresh token along with related access token
        """
        AccessToken.objects.get(id=self.access_token.id).revoke()
        self.delete()

    def __str__(self):
        return self.token


def get_application_model():
    """ Return the Application model that is active in this project. """
    try:
        app_label, model_name = oauth2_settings.APPLICATION_MODEL.split('.')
    except ValueError:
        e = "APPLICATION_MODEL must be of the form 'app_label.model_name'"
        raise ImproperlyConfigured(e)
    app_model = get_model(app_label, model_name)
    if app_model is None:
        e = "APPLICATION_MODEL refers to model {0} that has not been installed"
        raise ImproperlyConfigured(e.format(oauth2_settings.APPLICATION_MODEL))
    return app_model


def clear_expired():
    now = timezone.now()
    refresh_expire_at = None

    REFRESH_TOKEN_EXPIRE_SECONDS = oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS
    if REFRESH_TOKEN_EXPIRE_SECONDS:
        if not isinstance(REFRESH_TOKEN_EXPIRE_SECONDS, timedelta):
            try:
                REFRESH_TOKEN_EXPIRE_SECONDS = timedelta(seconds=REFRESH_TOKEN_EXPIRE_SECONDS)
            except TypeError:
                e = "REFRESH_TOKEN_EXPIRE_SECONDS must be either a timedelta or seconds"
                raise ImproperlyConfigured(e)
        refresh_expire_at = now - REFRESH_TOKEN_EXPIRE_SECONDS

    with transaction.atomic():
        if refresh_expire_at:
            RefreshToken.objects.filter(access_token__expires__lt=refresh_expire_at).delete()
        AccessToken.objects.filter(refresh_token__isnull=True, expires__lt=now).delete()
        Grant.objects.filter(expires__lt=now).delete()
