Getting started
===============

Django OAuth Toolkit provide a support layer for `Django REST Framework <http://django-rest-framework.org/>`_.
This tutorial is based on the Django REST Framework example and shows you how to easily integrate with it.

**NOTE**

The following code has been tested with Django 2.0.3 and Django REST Framework 3.7.7

Step 1: Minimal setup
---------------------

Create a virtualenv and install following packages using `pip`...

::

    pip install django-oauth-toolkit djangorestframework

Start a new Django project and add `'rest_framework'` and `'oauth2_provider'` to your `INSTALLED_APPS` setting.

.. code-block:: python

    INSTALLED_APPS = (
        'django.contrib.admin',
        ...
        'oauth2_provider',
        'rest_framework',
    )

Now we need to tell Django REST Framework to use the new authentication backend.
To do so add the following lines at the end of your `settings.py` module:

.. code-block:: python

    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': (
            'oauth2_provider.contrib.rest_framework.OAuth2Authentication',
        )
    }

Step 2: Create a simple API
---------------------------

Let's create a simple API for accessing users and groups.

Here's our project's root `urls.py` module:

.. code-block:: python

    from django.urls import path, include
    from django.contrib.auth.models import User, Group
    from django.contrib import admin
    admin.autodiscover()

    from rest_framework import generics, permissions, serializers

    from oauth2_provider.contrib.rest_framework import TokenHasReadWriteScope, TokenHasScope


    # first we define the serializers
    class UserSerializer(serializers.ModelSerializer):
        class Metaclass UserList(generics.ListAPIView):                                                                                                                                                                           
       permission_classes = [permissions.IsAuthenticated, TokenHasReadWriteScope]                                                                                                                                  
       queryset = User.objects.all()                                                                                                                                                                               
       serializer_class = UserSerializer:
            model = User
            fields = ("username", "email", "first_name", "last_name", )


    class GroupSerializer(serializers.ModelSerializer):
        class Meta:
            model = Group
            fields = ("name", )


    # Create the API views
    class UserList(generics.ListAPIView):
       permission_classes = [permissions.IsAuthenticated, TokenHasReadWriteScope]
       queryset = User.objects.all()
       serializer_class = UserSerializer


    class GroupList(generics.ListAPIView):
       permission_classes = [permissions.IsAuthenticated, TokenHasScope]
       required_scopes = ['groups']
       queryset = Group.objects.all()
       serializer_class = GroupSerializer

    
    # Wire up our API using automatic URL routing.
    # Additionally, we include login URLs for the browseable API.
    urlpatterns = [
        path('admin/', admin.site.urls),
        path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
        path('users/', UserList.as_view()),
        path('groups/', GroupList.as_view()),
        # ...
    ]

Also add the following to your `settings.py` module:

.. code-block:: python

    OAUTH2_PROVIDER = {
        # this is the list of available scopes
        'SCOPES': {'read': 'Read scope', 'write': 'Write scope', 'groups': 'Access to your groups'}
    }

    REST_FRAMEWORK = {
        # ...

        'DEFAULT_PERMISSION_CLASSES': (
            'rest_framework.permissions.IsAuthenticated',
        )
    }

`OAUTH2_PROVIDER.SCOPES` setting parameter contains the scopes that the application will be aware of,
so we can use them for permission check.

Now run the following commands:

::

    python manage.py migrate
    python manage.py createsuperuser
    python manage.py runserver

The first command creates the tables, the second creates the admin user account and the last one
runs the application.

Next thing you should do is to login in the admin at

::

    http://localhost:8000/admin

and create some users and groups that will be queried later through our API.


Step 3: Register an application
-------------------------------

To obtain a valid access_token first we must register an application. DOT has a set of customizable
views you can use to CRUD application instances, just point your browser at:

::

    http://localhost:8000/o/applications/

Click on the link to create a new application and fill the form with the following data:

* Name: *just a name of your choice*
* Client Type: *confidential*
* Authorization Grant Type: *Resource owner password-based*

Save your app!

Step 4: Get your token and use your API
---------------------------------------

At this point we're ready to request an access_token. Open your shell

::

    curl -X POST -d "grant_type=password&username=<user_name>&password=<password>" -u"<client_id>:<client_secret>" http://localhost:8000/o/token/

The *user_name* and *password* are the credential of the users registered in your :term:`Authorization Server`, like any user created in Step 2.
Response should be something like:

.. code-block:: javascript

    {
        "access_token": "<your_access_token>",
        "token_type": "Bearer",
        "expires_in": 36000,
        "refresh_token": "<your_refresh_token>",
        "scope": "read write groups"
    }

Grab your access_token and start using your new OAuth2 API:

::

    # Retrieve users
    curl -H "Authorization: Bearer <your_access_token>" http://localhost:8000/users/
    curl -H "Authorization: Bearer <your_access_token>" http://localhost:8000/users/1/

    # Retrieve groups
    curl -H "Authorization: Bearer <your_access_token>" http://localhost:8000/groups/

    # Insert a new user
    curl -H "Authorization: Bearer <your_access_token>" -X POST -d"username=foo&password=bar" http://localhost:8000/users/

Step 5: Testing Restricted Access
---------------------------------

Let's try to access resources using a token with a restricted scope adding a `scope` parameter to the token request

::

    curl -X POST -d "grant_type=password&username=<user_name>&password=<password>&scope=read" -u"<client_id>:<client_secret>" http://localhost:8000/o/token/

As you can see the only scope provided is `read`:

.. code-block:: javascript

    {
        "access_token": "<your_access_token>",
        "token_type": "Bearer",
        "expires_in": 36000,
        "refresh_token": "<your_refresh_token>",
        "scope": "read"
    }

We now try to access our resources:

::

    # Retrieve users
    curl -H "Authorization: Bearer <your_access_token>" http://localhost:8000/users/
    curl -H "Authorization: Bearer <your_access_token>" http://localhost:8000/users/1/

Ok, this one works since users read only requires `read` scope.

::

    # 'groups' scope needed
    curl -H "Authorization: Bearer <your_access_token>" http://localhost:8000/groups/

    # 'write' scope needed
    curl -H "Authorization: Bearer <your_access_token>" -X POST -d"username=foo&password=bar" http://localhost:8000/users/

You'll get a `"You do not have permission to perform this action"` error because your access_token does not provide the
required scopes `groups` and `write`.
