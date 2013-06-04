"""
All responses will have Access-Control-Allow-Origin, and Access-Control-Allow-Methods
header items.

If a request has Access-Control-Request-Methods in the header, then an
HttpResponse object is returned with header containing Access-Control-Allow-Origin,
Access-Control-Allow-Methods, and Access-Control-Allow-Headers items.

"""
from django import http
from django.conf import settings


XS_SHARING_ALLOWED_ORIGINS = getattr(settings, "XS_SHARING_ALLOWED_ORIGINS", '*')
XS_SHARING_ALLOWED_METHODS = getattr(settings, "XS_SHARING_ALLOWED_METHODS", ['POST', 'GET', 'OPTIONS', 'PUT', 'DELETE'])
XS_SHARING_ALLOWED_HEADERS = getattr(settings, "XS_SHARING_ALLOWED_HEADERS", ['x-requested-with', 'content-type', 'accept', 'origin', 'authorization'])


class XsSharingMiddleware(object):
    """
        This middleware allows cross-domain XHR using the html5 postMessage API.

        eg.
        Access-Control-Allow-Origin: http://api.example.com
        Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE
        Access-Control-Allow-Headers: ["Content-Type"]

    """
    def process_request(self, request):

        if 'HTTP_ACCESS_CONTROL_REQUEST_METHOD' in request.META:
            response = http.HttpResponse()
            response['Access-Control-Allow-Origin'] = XS_SHARING_ALLOWED_ORIGINS
            response['Access-Control-Allow-Methods'] = ",".join(XS_SHARING_ALLOWED_METHODS)
            response['Access-Control-Allow-Headers'] = ",".join(XS_SHARING_ALLOWED_HEADERS)
            return response

        return None

    def process_response(self, request, response):
        # Avoid unnecessary work
        if response.has_header('Access-Control-Allow-Origin'):
            return response

        response['Access-Control-Allow-Origin'] = XS_SHARING_ALLOWED_ORIGINS
        response['Access-Control-Allow-Methods'] = ",".join(XS_SHARING_ALLOWED_METHODS)

        return response
