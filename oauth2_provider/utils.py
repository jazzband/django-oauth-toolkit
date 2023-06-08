import functools

from jwcrypto import jwk


@functools.lru_cache()
def jwk_from_pem(pem_string):
    """
    A cached version of jwcrypto.JWK.from_pem.
    Converting from PEM is expensive for large keys such as those using RSA.
    """
    return jwk.JWK.from_pem(pem_string.encode("utf-8"))
