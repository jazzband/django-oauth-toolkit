from django.core.validators import URLValidator


def validate_uris(value):
    """
    This validator ensures that `value` contains valid blank-separated urls"
    """
    v = URLValidator()
    for uri in value.split():
        v(uri)
