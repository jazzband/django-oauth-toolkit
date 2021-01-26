from copy import deepcopy

from django.conf import settings


# A set of OAUTH2_PROVIDER settings dicts that can be used in tests

DEFAULT_SCOPES_RW = {"DEFAULT_SCOPES": ["read", "write"]}
DEFAULT_SCOPES_RO = {"DEFAULT_SCOPES": ["read"]}
OIDC_SETTINGS_RW = {
    "OIDC_ISS_ENDPOINT": "http://localhost",
    "OIDC_USERINFO_ENDPOINT": "http://localhost/userinfo/",
    "OIDC_RSA_PRIVATE_KEY": settings.OIDC_RSA_PRIVATE_KEY,
    "SCOPES": {
        "read": "Reading scope",
        "write": "Writing scope",
        "openid": "OpenID connect",
    },
    "DEFAULT_SCOPES": ["read", "write"],
}
OIDC_SETTINGS_RO = deepcopy(OIDC_SETTINGS_RW)
OIDC_SETTINGS_RO["DEFAULT_SCOPES"] = ["read"]
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