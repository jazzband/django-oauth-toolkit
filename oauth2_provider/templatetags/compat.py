from django import template

from ..compat import url as url_compat

register = template.Library()


@register.tag
def url(parser, token):
    return url_compat(parser, token)
