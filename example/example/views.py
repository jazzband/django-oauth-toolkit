import urllib

from django.http import HttpResponse
from django.core.urlresolvers import reverse
from django.views.generic import FormView, TemplateView

from .forms import ConsumerForm

CLIENT_ID = '3b2b4de5b14e2c708a01b0a349b9eab5a7615daa'
CLIENT_SECRET = '8e8bfeafdc7c16bdb80e5809afe994e5aec8b63adfa31cd127677318f872201880d38082af71320e36aec3e9847ff70c2b3d2555eb53ca12947c254add7d2c20'


def home(request):
    """
    Project homepage, show links to:
     * admin
     * consumer page
     * provider page
    """
    query_string = urllib.urlencode({
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': 'http://localhost:8000' + reverse('exchange'),
    })
    auth_url = "{url}?{qs}".format(url=reverse('authorize'), qs=query_string)
    html = '<a href="{}">Go and authorize</a>'.format(auth_url)

    return HttpResponse(html)


def exchange(request):
    import requests
    from requests.auth import HTTPBasicAuth

    auth_code = request.GET.get('code', None)
    if not auth_code:
        return HttpResponse()

    token_request_data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': 'http://localhost:8000' + reverse('exchange')[:-1],
    }
    r = requests.post('http://localhost:8000' + reverse('token'), params=token_request_data,
                      auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET))
    return HttpResponse(r)


class ConsumerView(FormView):
    form_class = ConsumerForm
    success_url = '/consumer/auth-link/'
    template_name = 'example/consumer.html'

    def __init__(self, **kwargs):
        self.authorization_link = None
        super(ConsumerView, self).__init__(**kwargs)

    def get_success_url(self):
        url = super(ConsumerView, self).get_success_url()
        return '{url}?{qs}'.format(url=url, qs=urllib.urlencode({'authorization_link': self.authorization_link}))

    def post(self, request, *args, **kwargs):
        self.request = request
        return super(ConsumerView, self).post(request, *args, **kwargs)

    def form_valid(self, form):
        qs = urllib.urlencode({
            'client_id': form.cleaned_data['client_id'],
            'response_type': 'code',
            'state': 'random_state_string',
            'redirect_uri': self.request.build_absolute_uri(reverse('exchange')),
        })
        self.authorization_link = "{url}?{qs}".format(url=form.cleaned_data['authorization_url'], qs=qs)
        return super(ConsumerView, self).form_valid(form)


class ConsumerLinkView(TemplateView):
    template_name = 'example/consumer-link.html'

    def get(self, request, *args, **kwargs):
        kwargs['authorization_link'] = request.GET['authorization_link']
        return super(ConsumerLinkView, self).get(request, *args, **kwargs)