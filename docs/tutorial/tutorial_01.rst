Part 1 - make a provider in a minute
====================================

Scenario
--------
You want to make your own :term:`Authorization Server`, managing the client applications which will have access to a
certain API, releasing the tokens and so on...

Start your app
--------------
During this tutorial you will make and XHR POST from an Heroku deployed app to your localhost instance.
To achieve this operation you need a properly configured Django server with `django-cors-headers` app installed, since
the domain that originated the request (the app on Heroku) is different from the destination domain (your local instance).
Such "cross-domain" requests are by default forbidden by web browsers unless you use CORS.
You can read more about `CORS here <http://en.wikipedia.org/wiki/Cross-origin_resource_sharing>`_.

Create a virtualenv and install `django-oauth-toolkit` and `django-cors-headers`:

::

    pip install django-oauth-toolkit django-cors-headers

start a Django project, add `oauth2_provider` and `corsheaders` to the installed apps, enable the admin.

.. code-block:: python

    INSTALLED_APPS = {
        'django.contrib.admin',
        # ...
        'oauth2_provider',
        'corsheaders',
    }

Include the Django OAuth Toolkit urls in your `urls.py`, choose the urlspace you prefer, for example:

.. code-block:: python

    urlpatterns = patterns(
        '',
        url(r'^admin/', include(admin.site.urls)),
        url(r'^o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
        # ...
    )

Include this middleware in your `settings.py`:

.. code-block:: python

    MIDDLEWARE_CLASSES = (
        # ...
        'corsheaders.middleware.CorsMiddleware',
        # ...
    )

Configure this setting to allow CORS requests from all domains (just for the scope of this tutorial):

.. code-block:: python

    CORS_ORIGIN_ALLOW_ALL = True

As a final steps, make a syncdb, start the internal server and login into the admin with your credentials.

Create an OAuth2 Client Application
-----------------------------------
An application which wants to perform API requests must be registered in the :term:`Authorization Server` to be properly
identified. This operation is usually done manually by a developer, who asks for an account in the
:term:`Authorization Server` and gets access to some sort of backoffice where she can register her application, which
will act as a :term:`Client` (or :term:`Application` in the Django OAuth Toolkit lingo).
Let's perform exactly this operation.
In the admin, section `Oauth2_Provider`, add an Application instance.
`Client id` and `Client Secret` are automatically generated, you have to provide the rest of the informations:

 * `User`: the owner of the Application (tipically a developer), could be the current logged in user.

 * `Redirect uris`: at a certain point of the token request process, the :term:`Authorization Server` needs to know a
   list of url (must be at least one) in the client application service where delivering the :term:`Authorization Token`.
   Developers have the responsibility to correctly provide this value. For this tutorial, paste verbatim the value
   `http://django-oauth-toolkit.herokuapp.com/consumer/exchange/`

 * `Client type`: this value affects the security level at which some communications between the client application and
   the authorization server are performed. For this tutorial choose *Confidential*.

 * `Authorization grant type`: choose *Authorization code*

 * `Name`: this is the name of the client application on the server, and will be displayed on the authorization request
   page, where users can allow/deny access to their data.

Take note of the `Client id` and the `Client Secret` then logout (this is needed only for testing the authorization
process we'll explain shortly)

Test your authorization server
------------------------------
Your authorization server is ready and can start releasing access tokens. To test the process you need an OAuth2
consumer: if you know OAuth2 enough you can use curl, requests or anything can speak http. For the rest of us, we have
a `consumer service <http://django-oauth-toolkit.herokuapp.com/consumer/>`_ deployed on Heroku you can use to test your
provider.

Build an authorization link for your users
++++++++++++++++++++++++++++++++++++++++++
The process of authorizing an application to access OAuth2 protected data in an :term:`Authorization Code` flow is always
started by the user. You have to prompt your users with a special link they click to start the process. Go to the
`Consumer <http://django-oauth-toolkit.herokuapp.com/consumer/>`_ page and fill the form with the data of the
application you created earlier on this tutorial. Submit the form, you'll get the link your users should follow to get
to the authorization page.

Authorize the application
+++++++++++++++++++++++++
When the user clicks the link, she is redirected to your (possibly local) :term:`Authorization Server`. If you're not logged in
in your Django admin, at this point you should be prompted for username and password. This is because the authorization
page is login protected by django-oauth-toolkit. Login, then you should see the not so cute form user can use to give
her authorization to the client application. Flag the *Allow* checkbox and click *Authorize*, you will be redirected
again on the consumer service.

Exchange the token
++++++++++++++++++
At this point your autorization server redirected the user to a special page on the consumer passing in an
:term:`Authorization Code`, a special token the consumer will use to obtain the final access token.
This operation is usually done automatically by the client application during the request/response cycle, but we cannot
make a POST request from Heroku to your localhost, so we proceed manually with this step. Fill the form with the
missing data and click *Submit*.
If everything is ok, you will be routed to another page showing your access token, the token type, its lifetime and
the :term:`Refresh Token`.

Refresh the token
+++++++++++++++++
The page showing the access token retrieved from the :term:`Authorization Server` also let you make a POST request to
the server itself to swap the refresh token for another, brand new access token.
Just fill in the missing form fields and click the Refresh button: if everything goes smooth you will se the access and
refresh token change their values, otherwise you will likely see an error message.
When finished playing with your authorization server, take note of both the access and refresh tokens, we will use them
for the next part of the tutorial.

So let's make an API and protect it with your OAuth2 tokens in the :doc:`part 2 of the tutorial <tutorial_02>`.