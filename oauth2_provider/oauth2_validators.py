from __future__ import unicode_literals

import time
import calendar

import six
import base64
import binascii
import hashlib
import re
import logging
import json
from datetime import timedelta

from django.utils import timezone
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
from oauthlib.oauth2 import RequestValidator

from .utils import build_claims_doc
from .compat import unquote_plus
from .models import Grant, AccessToken, RefreshToken, get_application_model, AbstractApplication
from .settings import oauth2_settings

log = logging.getLogger('oauth2_provider')

GRANT_TYPE_MAPPING = {
    'authorization_code': (AbstractApplication.GRANT_AUTHORIZATION_CODE,),
    'password': (AbstractApplication.GRANT_PASSWORD,),
    'client_credentials': (AbstractApplication.GRANT_CLIENT_CREDENTIALS,),
    'refresh_token': (AbstractApplication.GRANT_AUTHORIZATION_CODE, AbstractApplication.GRANT_PASSWORD,
                      AbstractApplication.GRANT_CLIENT_CREDENTIALS),
    'openid': (AbstractApplication.GRANT_OPENID_CONNECT)
}


class OAuth2Validator(RequestValidator):
    def _extract_basic_auth(self, request):
        """
        Return authentication string if request contains basic auth credentials, else return None
        """
        auth = request.headers.get('HTTP_AUTHORIZATION', None)
        if not auth:
            return None

        splitted = auth.split(' ', 1)
        if len(splitted) != 2:
            return None
        auth_type, auth_string = splitted

        if auth_type != "Basic":
            return None

        return auth_string

    def _authenticate_basic_auth(self, request):
        """
        Authenticates with HTTP Basic Auth.

        Note: as stated in rfc:`2.3.1`, client_id and client_secret must be encoded with
        "application/x-www-form-urlencoded" encoding algorithm.
        """
        auth_string = self._extract_basic_auth(request)
        if not auth_string:
            return False

        try:
            encoding = request.encoding or settings.DEFAULT_CHARSET or 'utf-8'
        except AttributeError:
            encoding = 'utf-8'

        # Encode auth_string to bytes. This is needed for python3.2 compatibility
        # because b64decode function only supports bytes type in input.
        if isinstance(auth_string, six.string_types):
            auth_string = auth_string.encode(encoding)

        try:
            b64_decoded = base64.b64decode(auth_string)
        except (TypeError, binascii.Error):
            log.debug("Failed basic auth: %s can't be decoded as base64", auth_string)
            return False

        try:
            auth_string_decoded = b64_decoded.decode(encoding)
        except UnicodeDecodeError:
            log.debug("Failed basic auth: %s can't be decoded as unicode by %s",
                      auth_string,
                      encoding)
            return False

        client_id, client_secret = map(unquote_plus, auth_string_decoded.split(':', 1))

        if self._load_application(client_id, request) is None:
            log.debug("Failed basic auth: Application %s does not exist" % client_id)
            return False
        elif request.client.client_secret != client_secret:
            log.debug("Failed basic auth: wrong client secret %s" % client_secret)
            return False
        else:
            return True

    def _authenticate_request_body(self, request):
        """
        Try to authenticate the client using client_id and client_secret parameters
        included in body.

        Remember that this method is NOT RECOMMENDED and SHOULD be limited to clients unable to
        directly utilize the HTTP Basic authentication scheme. See rfc:`2.3.1` for more details.
        """
        # TODO: check if oauthlib has already unquoted client_id and client_secret
        try:
            client_id = request.client_id
            client_secret = request.client_secret
        except AttributeError:
            return False

        if self._load_application(client_id, request) is None:
            log.debug("Failed body auth: Application %s does not exists" % client_id)
            return False
        elif request.client.client_secret != client_secret:
            log.debug("Failed body auth: wrong client secret %s" % client_secret)
            return False
        else:
            return True

    def _load_application(self, client_id, request):
        """
        If request.client was not set, load application instance for given client_id and store it
        in request.client
        """

        # we want to be sure that request has the client attribute!
        assert hasattr(request, "client"), "'request' instance has no 'client' attribute"

        Application = get_application_model()
        try:
            request.client = request.client or Application.objects.get(client_id=client_id)
            return request.client
        except Application.DoesNotExist:
            log.debug("Failed body authentication: Application %s does not exist" % client_id)
            return None

    def _get_user_claims_provider(self):
        if not hasattr(self, '_user_claims_provider'):
            self._user_claims_provider = oauth2_settings.OPENID_USER_CLAIMS_PROVIDER_CLASS()
        return self._user_claims_provider

    def client_authentication_required(self, request, *args, **kwargs):
        """
        Determine if the client has to be authenticated

        This method is called only for grant types that supports client authentication:
            * Authorization code grant
            * Resource owner password grant
            * Refresh token grant

        If the request contains authorization headers, always authenticate the client no matter
        the grant type.

        If the request does not contain authorization headers, proceed with authentication only if
        the client is of type `Confidential`.

        If something goes wrong, call oauthlib implementation of the method.
        """
        if self._extract_basic_auth(request):
            return True

        try:
            if request.client_id and request.client_secret:
                return True
        except AttributeError:
            log.debug("Client id or client secret not provided, proceed evaluating if authentication is required...")
            pass

        self._load_application(request.client_id, request)
        if request.client:
            return request.client.client_type == AbstractApplication.CLIENT_CONFIDENTIAL

        return super(OAuth2Validator, self).client_authentication_required(request,
                                                                           *args, **kwargs)

    def authenticate_client(self, request, *args, **kwargs):
        """
        Check if client exists and it's authenticating itself as in rfc:`3.2.1`

        First we try to authenticate with HTTP Basic Auth, and that is the PREFERRED
        authentication method.
        Whether this fails we support including the client credentials in the request-body, but
        this method is NOT RECOMMENDED and SHOULD be limited to clients unable to directly utilize
        the HTTP Basic authentication scheme. See rfc:`2.3.1` for more details
        """
        authenticated = self._authenticate_basic_auth(request)

        if not authenticated:
            authenticated = self._authenticate_request_body(request)

        return authenticated

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """
        If we are here, the client did not authenticate itself as in rfc:`3.2.1` and we can
        proceed only if the client exists and it's not of type 'Confidential'.
        Also assign Application instance to request.client.
        """
        if self._load_application(client_id, request) is not None:
            log.debug("Application %s has type %s" % (client_id, request.client.client_type))
            return request.client.client_type != AbstractApplication.CLIENT_CONFIDENTIAL
        return False

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        """
        Ensure the redirect_uri is listed in the Application instance redirect_uris field
        """
        grant = Grant.objects.get(code=code, application=client)
        return grant.redirect_uri_allowed(redirect_uri)

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        """
        Remove the temporary grant used to swap the authorization token
        """
        grant = Grant.objects.get(code=code, application=request.client)
        grant.delete()

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """
        Ensure an Application exists with given client_id. If it exists, it's assigned to
        request.client.
        """
        return self._load_application(client_id, request) is not None

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return request.client.default_redirect_uri

    def validate_bearer_token(self, token, scopes, request):
        """
        When users try to access resources, check that provided token is valid
        """
        if not token:
            return False

        try:
            access_token = AccessToken.objects.select_related("application", "user").get(
                token=token)
            if access_token.is_valid(scopes):
                request.client = access_token.application
                request.user = access_token.user

                # this is needed by django rest framework
                request.access_token = access_token
                if request.access_token.claims:
                    request.access_token.claims = json.loads(request.access_token.claims)
                return True
            return False
        except AccessToken.DoesNotExist:
            return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        try:
            grant = Grant.objects.get(code=code, application=client)
            if not grant.is_expired():
                request.scopes = grant.scope.split(' ')
                request.user = grant.user
                if grant.claims:
                    request.claims = json.loads(grant.claims)
                return True
            return False

        except Grant.DoesNotExist:
            return False

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        """
        Validate both grant_type is a valid string and grant_type is allowed for current workflow
        """
        assert(grant_type in GRANT_TYPE_MAPPING)  # mapping misconfiguration
        return request.client.authorization_grant_type in GRANT_TYPE_MAPPING[grant_type]

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        """
        We currently do not support the Authorization Endpoint Response Types registry as in
        rfc:`8.4`, so validate the response_type only if it matches 'code' or 'token'
        """
        if response_type == 'code':
            return client.authorization_grant_type == AbstractApplication.GRANT_AUTHORIZATION_CODE \
                    or client.authorization_grant_type == AbstractApplication.GRANT_OPENID_CONNECT
        elif response_type == 'token':
            return client.authorization_grant_type == AbstractApplication.GRANT_IMPLICIT
        elif response_type in ['code token', 'code id_token', 'code token id_token']:
            # TODO: should these be accepting of alternate orders e.g. 'code id_token token' ?
            return client.authorization_grant_type == AbstractApplication.GRANT_OPENID_CONNECT
        else:
            return False

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """
        Ensure required scopes are permitted (as specified in the settings file)
        """
        return set(scopes).issubset(set(oauth2_settings._SCOPES))

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return oauth2_settings._DEFAULT_SCOPES

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        return request.client.redirect_uri_allowed(redirect_uri)

    def get_id_token(self, token, token_handler, request):
        """

        {
            # Issuer Identifier for the Issuer of the response
            "iss": "https://server.example.com",

            # Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
            "sub": "24400320",

            # Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
            "aud": "s6BhdRkqt3",

            # Expiration time on or after which the ID Token MUST NOT be accepted for processing. The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time. See RFC 3339 [RFC3339] for details regarding date/times in general and UTC in particular.
            "exp": 1311281970,

            # Time at which the JWT was issued. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
            "iat": 1311280970,

            # Time when the End-User authentication occurred. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time. When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL. (The auth_time Claim semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time response parameter.)
            "auth_time": 1311280969

            # The Access Token hash value
            "at_hash": ABCDEF123

            # The Authorization Code hash value
            "c_hash": FEDCBA321
        }


        :param token:
        :type token: oauth2.rfc6749.tokens.OAuth2Token
        :param token_handler:
        :type token_handler:
        :param request:
        :type request:
        :return:
        :rtype:
        """

        gmnow = time.gmtime()
        epoch_now = calendar.timegm(gmnow)
        exp = epoch_now + oauth2_settings.OPENID_CONNECT_ID_TOKEN_LIFETIME

        user_claims_provider = self._get_user_claims_provider()

        try:
            user_auth_time = int(time.mktime(request.user.last_login.timetuple()))
        except:
            log.error("Unable to find last login time for {}".format(request.user))
            user_auth_time = epoch_now

        id_token = {
            "iss": oauth2_settings.OPENID_CONNECT_TOKEN_ISSUER, # TODO: needs real solution
            "sub": getattr(request.user, 'pk', None),
            "aud": request.client.client_id,
            "exp": exp,
            "iat": epoch_now,
            "auth_time": user_auth_time
        }

        algorithm_name = oauth2_settings.OPENID_CONNECT_ID_TOKEN_ALG

        hashlib_info = None
        if algorithm_name != 'none':
            hashlib_info = {
                "alg": algorithm_name,
                "num_bits_in_alg": self._get_num_bits_from_algorithm(algorithm_name)
            }
            hashlib_info['digester'] = hashlib.new("sha%s" % hashlib_info.get('num_bits_in_alg'))

        if token.get('access_token'):
            self.add_element_hash_to_id_token(id_token, 'at_hash', token.get('access_token'), hashlib_info=hashlib_info)

        if request.code:
            self.add_element_hash_to_id_token(id_token, 'c_hash', request.code, hashlib_info=hashlib_info)

        if user_claims_provider and request.claims:

            claims_doc = build_claims_doc(request.scopes, request.claims, "id_token")

            claims = user_claims_provider.get_claims(request.user, request.client, claims_doc, request)
            if claims:
                id_token.update(claims)

        return self.create_jws(id_token, request.client.client_secret, algorithm_name)

    def create_jws(self, id_token, client_secret, algorithm):
        from jose import jws
        return jws.sign(id_token, client_secret, algorithm=algorithm)

    def add_element_hash_to_id_token(self, id_token, element_name, value_to_hash, hashlib_info=None, algorithm=None):

        # at_hash
        # Access Token hash value. Its value is the base64url encoding of the left-most half of the
        # hash of the octets of the ASCII representation of the access_token value, where the hash
        # algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's
        # JOSE Header. For instance, if the alg is RS256, hash the access_token value with SHA-256, then
        # take the left-most 128 bits and base64url encode them. The at_hash value is a case sensitive string.
        # If the ID Token is issued from the Authorization Endpoint with an access_token value, which is the
        # case for the response_type value code id_token token, this is REQUIRED; otherwise, its inclusion is OPTIONAL.
        #
        # c_hash
        # Code hash value. Its value is the base64url encoding of the left-most half of the hash of the octets of
        # the ASCII representation of the code value, where the hash algorithm used is the hash algorithm used in
        # the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is HS512, hash the code
        # value with SHA-512, then take the left-most 256 bits and base64url encode them. The c_hash value is a case
        # sensitive string.
        # If the ID Token is issued from the Authorization Endpoint with a code, which is the case for the
        # response_type values code id_token and code id_token token, this is REQUIRED; otherwise, its inclusion
        # is OPTIONAL.

        # The table below is the set of "alg" (algorithm) Header Parameter
        # values defined by this specification for use with JWS, each of which
        # is explained in more detail in the following sections:
        #
        # +--------------+-------------------------------+--------------------+
        # | "alg" Param  | Digital Signature or MAC      | Implementation     |
        # | Value        | Algorithm                     | Requirements       |
        # +--------------+-------------------------------+--------------------+
        # | HS256        | HMAC using SHA-256            | Required           |
        # | HS384        | HMAC using SHA-384            | Optional           |
        # | HS512        | HMAC using SHA-512            | Optional           |
        # | RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
        # |              | SHA-256                       |                    |
        # | RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
        # |              | SHA-384                       |                    |
        # | RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
        # |              | SHA-512                       |                    |
        # | ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
        # | ES384        | ECDSA using P-384 and SHA-384 | Optional           |
        # | ES512        | ECDSA using P-521 and SHA-512 | Optional           |
        # | PS256        | RSASSA-PSS using SHA-256 and  | Optional           |
        # |              | MGF1 with SHA-256             |                    |
        # | PS384        | RSASSA-PSS using SHA-384 and  | Optional           |
        # |              | MGF1 with SHA-384             |                    |
        # | PS512        | RSASSA-PSS using SHA-512 and  | Optional           |
        # |              | MGF1 with SHA-512             |                    |
        # | none         | No digital signature or MAC   | Optional           |
        # |              | performed                     |                    |
        # +--------------+-------------------------------+--------------------+
        #
        # The use of "+" in the Implementation Requirements column indicates
        # that the requirement strength is likely to be increased in a future
        # version of the specification.

        if hashlib_info:
            num_bits_to_hash = hashlib_info.get('num_bits_in_alg') / 16
            hashlib = hashlib_info.get('digester')
            hashlib.update(value_to_hash)

            id_token[element_name] = base64.b64encode(hashlib.digest()[:num_bits_to_hash])

    def _get_num_bits_from_algorithm(self, algorithm_name):
        num_bits_in_alg = None
        if algorithm_name != "none":
            pattern = re.compile(r'[HREP]S(\d+)')
            match = pattern.match(algorithm_name)
            if match:
                num_bits_in_alg = int(match.group(1))
            else:
                log.debug("Unrecognized JWS signing algorithm %s" % algorithm_name)
        return num_bits_in_alg


    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        expires = timezone.now() + timedelta(
            seconds=oauth2_settings.AUTHORIZATION_CODE_EXPIRE_SECONDS)
        claims = ''
        if request.claims:
            claims = json.dumps(request.claims)
        g = Grant(application=request.client, user=request.user, code=code['code'],
                  expires=expires, redirect_uri=request.redirect_uri,
                  scope=' '.join(request.scopes), claims=claims)
        g.save()

    def save_bearer_token(self, token, request, *args, **kwargs):
        """
        Save access and refresh token, If refresh token is issued, remove old refresh tokens as
        in rfc:`6`
        """
        if request.refresh_token:
            # remove used refresh token
            try:
                RefreshToken.objects.get(token=request.refresh_token).revoke()
            except RefreshToken.DoesNotExist:
                assert()  # TODO though being here would be very strange, at least log the error

        expires = timezone.now() + timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        if request.grant_type == 'client_credentials':
            request.user = None

        claims = ''
        if request.claims:
            claims = json.dumps(request.claims)

        access_token = AccessToken(
            user=request.user,
            scope=token['scope'],
            expires=expires,
            token=token['access_token'],
            application=request.client,
            claims=claims)
        access_token.save()

        if 'refresh_token' in token:
            refresh_token = RefreshToken(
                user=request.user,
                token=token['refresh_token'],
                application=request.client,
                access_token=access_token
            )
            refresh_token.save()

        # TODO check out a more reliable way to communicate expire time to oauthlib
        token['expires_in'] = oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        """
        Revoke an access or refresh token.

        :param token: The token string.
        :param token_type_hint: access_token or refresh_token.
        :param request: The HTTP Request (oauthlib.common.Request)
        """
        if token_type_hint not in ['access_token', 'refresh_token']:
            token_type_hint = None

        token_types = {
            'access_token': AccessToken,
            'refresh_token': RefreshToken,
        }

        token_type = token_types.get(token_type_hint, AccessToken)
        try:
            token_type.objects.get(token=token).revoke()
        except ObjectDoesNotExist:
            for other_type in [_t for _t in token_types.values() if _t != token_type]:
                # slightly inefficient on Python2, but the queryset contains only one instance
                list(map(lambda t: t.revoke(), other_type.objects.filter(token=token)))

    def validate_user(self, username, password, client, request, *args, **kwargs):
        """
        Check username and password correspond to a valid and active User
        """
        u = authenticate(username=username, password=password)
        if u is not None and u.is_active:
            request.user = u
            return True
        return False

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Avoid second query for RefreshToken since this method is invoked *after*
        # validate_refresh_token.
        rt = request.refresh_token_instance
        return rt.access_token.scope

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """
        Check refresh_token exists and refers to the right client.
        Also attach User instance to the request object
        """
        try:
            rt = RefreshToken.objects.get(token=refresh_token)
            request.user = rt.user
            request.refresh_token = rt.token
            # Temporary store RefreshToken instance to be reused by get_original_scopes.
            request.refresh_token_instance = rt
            return rt.application == client

        except RefreshToken.DoesNotExist:
            return False
