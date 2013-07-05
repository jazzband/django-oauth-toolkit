from django.core.validators import URLValidator


def validate_uris(value):
    """
    TODO: add docs
    """
    v = URLValidator()
    for uri in value.split():
        v(uri)
