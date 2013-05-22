from .utils import long_hash, short_hash


class BaseHashGenerator(object):
    """
    All generators should extend this class overriding `.hash()` method.
    """
    def hash(self):
        raise NotImplementedError


class ClientIdGenerator(BaseHashGenerator):
    def hash(self):
        return short_hash()


class ClientSecretGenerator(BaseHashGenerator):
    def hash(self):
        return long_hash()


def generate_client_id():
    """
    Generate a suitable client id
    """
    client_id_generator = ""
    return ClientIdGenerator().hash()


def generate_client_secret():
    """
    Generate a suitable client secret
    """
    client_secret_generator = ""
    return ClientSecretGenerator().hash()
