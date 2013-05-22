import uuid
import hashlib


def short_hash():
    """
    Generate a unique short hash (40 bytes) which is suitable as a token, secret or id
    """
    return hashlib.sha1(uuid.uuid1().get_bytes()).hexdigest()


def long_hash():
    """
    Generate a unique long hash (128 bytes) which is suitable as a token, secret or id
    """
    return hashlib.sha512(uuid.uuid1().get_bytes()).hexdigest()
