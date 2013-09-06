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
    A custom server which bypasses OAuth controls for every GET request
    """
    def verify_request(self, uri, http_method='GET', body=None, headers=None, scopes=None):
        ok, request = super(MyServer, self).verify_request(uri, http_method, body, headers, scopes)
        if request.http_method == 'GET':
            ok = True  # possibly override failures
        return ok, request


@csrf_exempt  # so we can see 405 errors instead of 403
@require_http_methods(["GET"])
def get_system_info(request, *args, **kwargs):
    """
    A simple "read only" api endpoint, unprotected
    """
    data = {
        'DOT version': VERSION,
        'oauthlib version': '0.5.1',
        'Django version': get_version(),
    }

    return HttpResponse(json.dumps(data), content_type='application/json', *args, **kwargs)


@csrf_exempt
@protected_resource(server_cls=MyServer, scopes=["can_create_application"])
@require_http_methods(["GET", "POST"])
def applications_list(request, *args, **kwargs):
    """
    List resources with GET, create a new one with POST. With custom server_cls we bypass oauth2
    controls and let everyone list applications.
    """
    if request.method == 'GET':
        # hide default Application in the playground
        data = serializers.serialize("json", MyApplication.objects.exclude(pk=1))
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
        # hide default Application in the playground
        if resource.pk == 1:
            raise MyApplication.DoesNotExist
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