Part 3 - OAuth2 token authentication
====================================

Scenario
--------
You want to use an :term:`Access Token` to authenticate users against Django's authentication
system.

Setup a provider
----------------
You need a fully-functional OAuth2 provider which is able to release access tokens: just follow
the steps in :doc:`the part 1 of the tutorial <tutorial_01>`. To enable OAuth2 token authentication
you need a middleware that checks for tokens inside requests and a custom authentication backend
which takes care of token verification. In your settings.py:

.. code-block:: python

    AUTHENTICATION_BACKENDS = (
        'oauth2_provider.backends.OAuth2Backend',
        # Uncomment following if you want to access the admin
        #'django.contrib.auth.backends.ModelBackend'
        '...',
    )

    MIDDLEWARE_CLASSES = (
        '...',
        'oauth2_provider.middleware.OAuth2TokenMiddleware',
        '...',
    )

You will likely use the `django.contrib.auth.backends.ModelBackend` along with the OAuth2 backend
(or you might not be able to log in into the admin), only pay attention to the order in which
Django processes authentication backends.

If you put the OAuth2 backend *after* the AuthenticationMiddleware and `request.user` is valid,
the backend will do nothing; if `request.user` is the Anonymous user it will try to authenticate
the user using the OAuth2 access token.

If you put the OAuth2 backend *before* AuthenticationMiddleware, or AuthenticationMiddleware is
not used at all, it will try to authenticate user with the OAuth2 access token and set
`request.user` and `request._cached_user` fields so that AuthenticationMiddleware (when active)
will not try to get user from the session.

Protect your view
-----------------
The authentication backend will run smoothly with, for example, `login_required` decorators, so
that you can have a view like this in your `views.py` module:

.. code-block:: python

    from django.contrib.auth.decorators import login_required
    from django.http.response import HttpResponse

    @login_required()
    def secret_page(request, *args, **kwargs):
        return HttpResponse('Secret contents!', status=200)

To check everything works properly, mount the view above to some url:

.. code-block:: python

    urlpatterns = patterns(
        '',
        url(r'^secret$', 'my.views.secret_page', name='secret'),
        '...',
    )

You should have an :term:`Application` registered at this point, if you don't follow the steps in
the previous tutorials to create one. Obtain an :term:`Access Token`, either following the OAuth2
flow of your application or manually creating in the Django admin.
Now supposing your access token value is `123456` you can try to access your authenticated view:

::

    curl -H "Authorization: Bearer 123456" -X GET http://localhost:8000/secret
