Part 1 - make a provider in a minute
====================================

Scenario
--------
You want to make your own Authorization Server, managing the client applications which will have access to a certain
API, releasing the tokens and so on...

Start your app
--------------
Create a virtualenv and install django-oauth-toolkit:

    pip install django-oauth-toolkit

start a Django project, add `oauth2_provider` to the installed apps, enable the admin and make a syncdb.
Start the internal server and login into the admin with your credentials.

Create an OAuth2 Client Application
-----------------------------------
An application which wants to perform API requests must be registered in the Authorization Server to be properly
identified. This operation is usually done manually by a developer, who asks for an account in the Authorization Server
and gets access to some sort of backoffice where she can register her application. Let's perform exactly this operation.
In the admin, section `Oauth2_Provider`, add an Application instance.
`Client id` and `Client Secret` are automatically generated, you have to provide the rest of the informations:

 * `User`: the owner of the Application (tipically a developer), could be the current logged in user.

 * `Redirect uris`: at a certain point of the token request process, the Authorization Server needs to know a list of url
   (must be at least one) in the client application service where delivering the so called *authorization token*.
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
a consumer service deployed on Heroku you can use to test your provider.

Build an authorization link for your users
++++++++++++++++++++++++++++++++++++++++++
The process of authorizing an application to access OAuth2 protected data in an *Authorization code* flow is always
started by the user. You have to prompt your users with a special link they click to start the process. Go to the
`Consumer <http://django-oauth-toolkit.herokuapp.com/consumer/>`_ page and fill the form with the data of the
application you created earlier on this tutorial. Submit the form, you'll get the link your users should follow to get
to the authorization page.

Authorize the application
+++++++++++++++++++++++++
When the user clicks the link, she is redirected to your (possibly local) Authorization server. If you're not logged in
in your Django admin, at this point you should be prompted for username and password. This is because the authorization
page is login protected by django-oauth-toolkit. Login, then you should see the not so cute form user can use to give
her authorization to the client application. Flag the *Allow* checkbox and click *Authorize*, you will be redirected
again on the consumer service.

Exchange the token
++++++++++++++++++
At this point your Autorization server redirected the user to a special page on the consumer passing in an authorization
code, a special token the consumer will use to obtain the final access token. This operation is usually done automatically
by the client application during the request/response cycle, but we cannot make a POST request from Heroku to your
localhost, so we proceed manually with this step. Fill the form with the missing data and click *Submit*. A dialog will
appear with either your access token, or an error. If everything went smooth, together with the access token you get
its expiration time, the token type and a refresh token,

Refresh the token
+++++++++++++++++
TODO

Now that you have a provider, let's make an API and protect it with your OAuth2 tokens in the
:doc:`part 2 of the tutorial <tutorial_02>`.