from oauth2_provider.decorators import protected_resource
from oauth2_provider import VERSION

import json
from django.http import HttpResponse
from django import get_version
from django.views.decorators.csrf import csrf_exempt
from django.core import serializers
from django.views.decorators.http import require_http_methods
from django.http import HttpResponseBadRequest, HttpResponseNotFound

from oauthlib.oauth2 import Server

from .models import MyApplication


class MyServer(Server):
    """
    A custom server which bypasses OAuth controls for every GET request to show data on a web page
    """
    def verify_request(self, uri, http_method='GET', body=None, headers=None, scopes=None):
        ok, request = super(MyServer, self).verify_request(uri, http_method, body, headers, scopes)
        if request.http_method == 'GET':
            ok = True  # possibly override failures
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


@csrf_exempt
@protected_resource(server_cls=MyServer)
@require_http_methods(["GET", "POST"])
def applications_list(request, *args, **kwargs):
    """
    List resources with GET, create a new one with POST.
    Everyone on the Internet can retrieve the list of applications (just for didactic purposes :-)
    """
    if request.method == 'GET':
        data = serializers.serialize("json", MyApplication.objects.all())
        return HttpResponse(data, content_type='application/json', *args, **kwargs)
    elif request.method == 'POST':
        if request.is_ajax():
            try:
                data = json.loads(request.body)
                data['user'] = request.resource_owner
                obj = MyApplication.objects.create(**data)
                out = serializers.serialize("json", [obj])
            except (ValueError, TypeError):
                return HttpResponseBadRequest()

            return HttpResponse(out, content_type='application/json', status=201, *args, **kwargs)


@csrf_exempt
@protected_resource()
@require_http_methods(["GET", "PUT", "DELETE"])
def applications_detail(request, pk, *args, **kwargs):
    """
    Show resource with GET, update it with PUT, destroy with DELETE
    """
    try:
        resource = MyApplication.objects.filter(user=request.resource_owner).filter(pk=pk).get()
    except MyApplication.DoesNotExist:
        return HttpResponseNotFound()

    if request.method == 'GET':
        data = serializers.serialize("json", [resource])
        return HttpResponse(data, content_type='application/json', status=200, *args, **kwargs)
    elif request.method == 'PUT':
        try:
            data = json.loads(request.body)
            for k, v in data.iteritems():
                setattr(resource, k, v)
            resource.save()
            data = serializers.serialize("json", [resource])
            return HttpResponse(data, content_type='application/json')
        except (ValueError, TypeError):
            return HttpResponseBadRequest()
    elif request.method == 'DELETE':
        resource.delete()
        return HttpResponse(status=204)