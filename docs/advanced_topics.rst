Advanced topics
+++++++++++++++


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
    from oauth2_provider.models import AbstractApplication

    class MyApplication(AbstractApplication):
        logo = models.ImageField()
        agree = models.BooleanField()

Then you need to tell Django OAuth Toolkit which model you want to use to represent applications.
Write something like this in your settings module::

    OAUTH2_PROVIDER_APPLICATION_MODEL='your_app_name.MyApplication'

Be aware that, when you intend to swap the application model, you should create and run the 
migration defining the swapped application model prior to setting OAUTH2_PROVIDER_APPLICATION_MODEL. 
You'll run into models.E022 in Core system checks if you don't get the order right.

That's all, now Django OAuth Toolkit will use your model wherever an Application instance is needed.

    **Notice:** `OAUTH2_PROVIDER_APPLICATION_MODEL` is the only setting variable that is not namespaced, this
    is because of the way Django currently implements swappable models.
    See issue #90 (https://github.com/evonove/django-oauth-toolkit/issues/90) for details


.. _skip-auth-form:

Skip authorization form
=======================

Depending on the OAuth2 flow in use and the access token policy, users might be prompted for the
same authorization multiple times: sometimes this is acceptable or even desirable but other times it isn't.
To control DOT behaviour you can use the `approval_prompt` parameter when hitting the authorization endpoint.
Possible values are:

* `force` - users are always prompted for authorization.

* `auto` - users are prompted only the first time, subsequent authorizations for the same application
  and scopes will be automatically accepted.

Skip authorization completely for trusted applications
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You might want to completely bypass the authorization form, for instance if your application is an
in-house product or if you already trust the application owner by other means. To this end, you have to
set ``skip_authorization = True`` on the ``Application`` model, either programmaticaly or within the
Django admin. Users will *not* be prompted for authorization, even on the first use of the application.
