from copy import deepcopy

from django.conf import settings


# A set of OAUTH2_PROVIDER settings dicts that can be used in tests

DEFAULT_SCOPES_RW = {"DEFAULT_SCOPES": ["read", "write"]}
DEFAULT_SCOPES_RO = {"DEFAULT_SCOPES": ["read"]}
OIDC_SETTINGS_RW = {
    "OIDC_ENABLED": True,
    "OIDC_ISS_ENDPOINT": "http://localhost/o",
    "OIDC_USERINFO_ENDPOINT": "http://localhost/o/userinfo/",
    "OIDC_RSA_PRIVATE_KEY": settings.OIDC_RSA_PRIVATE_KEY,
    "OIDC_RSA_PRIVATE_KEYS_INACTIVE": settings.OIDC_RSA_PRIVATE_KEYS_INACTIVE,
    "SCOPES": {
        "read": "Reading scope",
        "write": "Writing scope",
        "openid": "OpenID connect",
    },
    "DEFAULT_SCOPES": ["read", "write"],
}
OIDC_SETTINGS_RO = deepcopy(OIDC_SETTINGS_RW)
OIDC_SETTINGS_RO["DEFAULT_SCOPES"] = ["read"]
OIDC_SETTINGS_EMAIL_SCOPE = deepcopy(OIDC_SETTINGS_RW)
OIDC_SETTINGS_EMAIL_SCOPE["SCOPES"].update({"email": "return email address"})
OIDC_SETTINGS_HS256_ONLY = deepcopy(OIDC_SETTINGS_RW)
del OIDC_SETTINGS_HS256_ONLY["OIDC_RSA_PRIVATE_KEY"]
REST_FRAMEWORK_SCOPES = {
    "SCOPES": {
        "read": "Read scope",
        "write": "Write scope",
        "scope1": "Scope 1",
        "scope2": "Scope 2",
        "resource1": "Resource 1",
    },
}
INTROSPECTION_SETTINGS = {
    "SCOPES": {
        "read": "Read scope",
        "write": "Write scope",
        "introspection": "Introspection scope",
        "dolphin": "eek eek eek scope",
    },
    "RESOURCE_SERVER_INTROSPECTION_URL": "http://example.org/introspection",
    "READ_SCOPE": "read",
    "WRITE_SCOPE": "write",
}
