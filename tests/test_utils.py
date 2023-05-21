from oauth2_provider import utils


def test_jwk_from_pem_caches_jwk():
    a_tiny_rsa_key = """-----BEGIN RSA PRIVATE KEY-----
MGQCAQACEQCxqYaL6GtPooVMhVwcZrCfAgMBAAECECyNmdsuHvMqIEl9/Fex27kC
CQDlc0deuSVrtQIJAMY4MTw2eCeDAgkA5VzfMykQ5yECCQCgkF4Zl0nHPwIJALPv
+IAFUPv3
-----END RSA PRIVATE KEY-----"""

    # For the same private key we expect the same object to be returned

    jwk1 = utils.jwk_from_pem(a_tiny_rsa_key)
    jwk2 = utils.jwk_from_pem(a_tiny_rsa_key)

    assert jwk1 is jwk2

    a_different_tiny_rsa_key = """-----BEGIN RSA PRIVATE KEY-----
MGMCAQACEQCvyNNNw4J201yzFVogcfgnAgMBAAECEE3oXe5bNlle+xU4EVHTUIEC
CQDpSvwIvDMSIQIJAMDk47DzG9FHAghtvg1TWpy3oQIJAL6NHlS+RBufAgkA6QLA
2GK4aDc=
-----END RSA PRIVATE KEY-----"""

    # But for a different key, a different object
    jwk3 = utils.jwk_from_pem(a_different_tiny_rsa_key)

    assert jwk3 is not jwk1
