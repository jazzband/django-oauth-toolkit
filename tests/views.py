from django.http import HttpResponse
from django.views.generic import View


class MockView(View):
    def post(self, request):
        return HttpResponse()
