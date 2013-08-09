Extending the Application model
===============================

An Application instance represents a :term:`Client` on the :term:`Authorization server`. Usually an Application is
issued to client's developers after they log in on an Authorization Server and pass in some data
which identify the Application itself (let's say, the application name). Django OAuth Toolkit
provides a very basic implementation of the Application model containing only the data strictly
required during all the OAuth processes but you will likely need some extra info, like application
logo, acceptance of some user agreement and so on.

.. class:: AbstractApplication(models.Model)

    This is the base class implementing the bare minimum for Django OAuth Toolkit to work

    * :attr:`client_id` The client identifier issued to the client during the registration process as described in :rfc:`2.2`
    * :attr:`user` ref to a Django user
    * :attr:`redirect_uris` The list of allowed redirect uri. The string consists of valid URLs separated by space
    * :attr:`client_type` Client type as described in :rfc:`2.1`
    * :attr:`authorization_grant_type` Authorization flows available to the Application
    * :attr:`client_secret` Confidential secret issued to the client during the registration process as described in :rfc:`2.2`
    * :attr:`name` Friendly name for the Application

Django OAuth Toolkit lets you extend the AbstractApplication model in a fashion like Django's
custom user models.

If you need, let's say, application logo and user agreement acceptance field, you can to this in
your Django app (provided that your app is in the list of the INSTALLED_APPS in your settings
module)::

    from django.db import models
    from oauth2_provider import AbstractApplication

    class MyApplication(AbstractApplication):
        logo = models.ImageField()
        agree = models.BooleanField()

Then you need to tell Django OAuth Toolkit which model you want to use to represent applications.
Write something like this in your settings module::

    OAUTH2_PROVIDER = {
        'APPLICATION_MODEL': 'your_app_name.MyApplication',
    }
That's all, now Django OAuth Toolkit will use your model wherever an Application instance is needed.
