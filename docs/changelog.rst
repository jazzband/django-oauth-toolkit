Changelog
=========

0.4.0 [in development]
----------------------

 * Bugfix #25: Bug in the Basic Auth parsing in Oauth2RequestValidator
 * Bugfix #24: Avoid generation of client_id with ":" colon char when using HTTP Basic Auth
 * Bugfix #21: IndexError when trying to authorize an application
 * Bugfix #9: Default_redirect_uri is mandatory when grant_type is implicit, authorization_code or all-in-one
 * Bugfix #22: Scopes need a verbose description

**Backwards incompatible changes in 0.4.0**

 * `SCOPE` attribute in settings is now a dictionary to store `{'scope_name': 'scope_description'}`

0.3.2 [2013-07-10]
------------------

 * Bugfix #37: Error in migrations with custom user on Django 1.5

0.3.1 [2013-07-10]
------------------

 * Bugfix #27: OAuthlib refresh token refactoring

0.3.0 [2013-06-14]
----------------------

 * `Django REST Framework <http://django-rest-framework.org/>`_ integration layer
 * Bugfix #13: Populate request with client and user in validate_bearer_token
 * Bugfix #12: Fix paths in documentation

**Backwards incompatible changes in 0.3.0**

 * `requested_scopes` parameter in ScopedResourceMixin changed to `required_scopes`

0.2.1 [2013-06-06]
------------------

 * Core optimizations

0.2.0 [2013-06-05]
------------------

 * Add support for Django1.4 and Django1.6
 * Add support for Python 3.3
 * Add a default ReadWriteScoped view
 * Add tutorial to docs

0.1.0 [2013-05-31]
------------------

 * Support OAuth2 Authorization Flows

0.0.0 [2013-05-17]
------------------

 * Discussion with Daniel Greenfeld at Django Circus
 * Ignition
