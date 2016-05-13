Part 2 - protect your APIs
==========================

Scenario
--------
It's very common for an :term:`Authorization Server` being also the :term:`Resource Server`, usually exposing an API to
let others access its own resources. Django OAuth Toolkit implements an easy way to protect the views of a Django
application with OAuth2, in this tutorial we will see how to do it.

Make your API
-------------
We start where we left the :doc:`part 1 of the tutorial <tutorial_01>`: you have an authorization server and we want it
to provide an API to access some kind of resources. We don't need an actual resource, so we will simply expose an
endpoint protected with OAuth2: let's do it in a *class based view* fashion!

Django OAuth Toolkit provides a set of generic class based view you can use to add OAuth behaviour to your views. Open
your `views.py` module and import the view:

.. code-block:: python

    from oauth2_provider.views.generic import ProtectedResourceView
    from django.http import HttpResponse

Then create the view which will respond to the API endpoint:

.. code-block:: python

    class ApiEndpoint(ProtectedResourceView):
        def get(self, request, *args, **kwargs):
            return HttpResponse('Hello, OAuth2!')

That's it, our API will expose only one method, responding to `GET` requests. Now open your `urls.py` and specify the
URL this view will respond to:

.. code-block:: python

    from django.conf.urls import patterns, url
    from oauth2_provider import views
    from django.conf import settings
    from .views import ApiEndpoint

    urlpatterns = patterns(
        '',
        url(r'^admin/', include(admin.site.urls)),

        # OAuth2 provider endpoints
        url(r'^o/authorize/$', views.AuthorizationView.as_view(), name="authorize"),
        url(r'^o/token/$', views.TokenView.as_view(), name="token"),
        url(r'^o/revoke-token/$', views.RevokeTokenView.as_view(), name="revoke-token"),

        url(r'^api/hello', ApiEndpoint.as_view()),  # a resource endpoint
    )

    if settings.DEBUG:
        # OAuth2 Application management views

        urlpatterns += patterns(
            '',
            url(r'^o/applications/$', views.ApplicationList.as_view(), name="application-list"),
            url(r'^o/applications/register/$', views.ApplicationRegistration.as_view(), name="application-register"),
            url(r'^o/applications/(?P<pk>\d+)/$', views.ApplicationDetail.as_view(), name="application-detail"),
            url(r'^o/applications/(?P<pk>\d+)/delete/$', views.ApplicationDelete.as_view(), name="application-delete"),
            url(r'^o/applications/(?P<pk>\d+)/update/$', views.ApplicationUpdate.as_view(), name="application-update"),
        )

You will probably want to write your own application views to deal with permissions and access control but the ones packaged with the library can get you started when developing the app.

Since we inherit from `ProtectedResourceView`, we're done and our API is OAuth2 protected - for the sake of the lazy
programmer.

Testing your API
----------------
Time to make requests to your API.

For a quick test, try accessing your app at the url `/api/hello` with your browser
and verify that it responds with a `403` (in fact no `HTTP_AUTHORIZATION` header was provided).
You can test your API with anything that can perform HTTP requests, but for this tutorial you can use the online
`consumer client <http://django-oauth-toolkit.herokuapp.com/consumer/client>`_.
Just fill the form with the URL of the API endpoint (i.e. http://localhost:8000/api/hello if you're on localhost) and
the access token coming from the :doc:`part 1 of the tutorial <tutorial_01>`. Going in the Django admin and get the
token from there is not considered cheating, so it's an option.

Try performing a request and check that your :term:`Resource Server` aka :term:`Authorization Server` correctly responds with
an HTTP 200.

:doc:`Part 3 of the tutorial <tutorial_03>` will show how to use an access token to authenticate
users.
