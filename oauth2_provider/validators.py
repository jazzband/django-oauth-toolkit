from django.core.validators import URLValidator


def validate_uris(value):
    """

    """
    v = URLValidator()
    for uri in value.split():
        v(uri)
