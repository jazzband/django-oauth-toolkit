from oauth2_provider.decorators import protected_resource
from oauth2_provider import VERSION

import json
from django.http import HttpResponse
from django import get_version
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.views.decorators.http import require_http_methods

from oauthlib.oauth2 import Server


class MyServer(Server):
    """
    A custom server which bypasses OAuth controls for every GET request to show data on a web page
    """
    def verify_request(self, uri, http_method='GET', body=None, headers=None, scopes=None):
        ok, request = super(MyServer, self).verify_request(uri, http_method, body, headers, scopes)
        ok = request.http_method == 'GET'
        return ok, request


@require_http_methods(["GET"])
def get_system_info(request, *args, **kwargs):
    """
    A simple "read only" api endpoint, unprotected
    """
    data = {
        'DOT version': VERSION,
        'oauthlib version': '0.5.0',
        'Django version': get_version(),
    }

    return HttpResponse(json.dumps(data), content_type='application/json', *args, **kwargs)


@protected_resource()
@require_http_methods(["GET", "POST"])
def applications_list(request, *args, **kwargs):
    """
    List resources with GET, create a new one with POST
    """
    pass


@protected_resource(server_cls=MyServer)
@require_http_methods(["GET", "PUT", "DELETE"])
def applications_detail():
    """
    Show resource with GET, update it with PUT, destroy with DELETE
    """
    pass
