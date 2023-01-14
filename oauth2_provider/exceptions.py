class OAuthToolkitError(Exception):
    """
    Base class for exceptions
    """

    def __init__(self, error=None, redirect_uri=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.oauthlib_error = error

        if redirect_uri:
            self.oauthlib_error.redirect_uri = redirect_uri


class FatalClientError(OAuthToolkitError):
    """
    Class for critical errors
    """

    pass


# TODO: Cleanup
class OIDCError(Exception):
    status_code = 400
    error = None

    def __init__(self, description=None):
        if description is not None:
            self.description = description

        message = "({}) {}".format(self.error, self.description)
        super().__init__(message)


class InvalidRequestFatalError(OIDCError):
    """
    For fatal errors, the request is missing a required parameter, includes
    an invalid parameter value, includes a parameter more than once, or is
    otherwise malformed.
    """

    error = "invalid_request"


class ClientIdMissmatch(InvalidRequestFatalError):
    description = "Missmatch between Client ID of the ID Token and provided the Client ID."


class InvalidOIDCClientError(InvalidRequestFatalError):
    description = "The Client is unknown or no client was included."


class MismatchingOIDCRedirectURIError(InvalidRequestFatalError):
    description = "Mismatching post logout redirect URI."


class InvalidIDTokenError(InvalidRequestFatalError):
    description = "The ID Token is expired, revoked, malformed, or invalid for other reasons."


class LogoutDenied(OIDCError):
    error = "logout_denied"
    description = "Logout was denied by the user."
