## Changelog
### 1.3.0 [unreleased]

* Fix a race condition in creation of AccessToken with external oauth2 server.
* **Backwards-incompatible** squashed migrations:
  If you are currently on a release < 1.2.0, you will need to first install 1.2.x then `manage.py migrate` before
  upgrading to >= 1.3.0.
* Bump django minimum to 2.1
* Dropped Python 3.4

### 1.2.0 [2018-06-03]

* **Compatibility**: Python 3.4 is the new minimum required version.
* **Compatibility**: Django 2.0 is the new minimum required version.
* **New feature**: Added TokenMatchesOASRequirements Permissions.
* validators.URIValidator has been updated to match URLValidator behaviour more closely.
* Moved `redirect_uris` validation to the application clean() method.


### 1.1.2 [2018-05-12]

* Return state with Authorization Denied error (RFC6749 section 4.1.2.1)
* Fix a crash with malformed base64 authentication headers
* Fix a crash with malformed IPv6 redirect URIs

### 1.1.1 [2018-05-08]

* **Critical**: Django OAuth Toolkit 1.1.0 contained a migration that would revoke all existing
  RefreshTokens (`0006_auto_20171214_2232`). This release corrects the migration.
  If you have already ran it in production, please see the following issue for more details:
  https://github.com/jazzband/django-oauth-toolkit/issues/589


### 1.1.0 [2018-04-13]

* **Notice**: The Django OAuth Toolkit project is now hosted by JazzBand.
* **Compatibility**: Django 1.11 is the new minimum required version. Django 1.10 is no longer supported.
* **Compatibility**: This will be the last release to support Django 1.11 and Python 2.7.
* **New feature**: Option for RFC 7662 external AS that uses HTTP Basic Auth.
* **New feature**: Individual applications may now override the `ALLOWED_REDIRECT_URI_SCHEMES`
  setting by returning a list of allowed redirect uri schemes in `Application.get_allowed_schemes()`.
* **New feature**: The new setting `ERROR_RESPONSE_WITH_SCOPES` can now be set to True to include required
  scopes when DRF authorization fails due to improper scopes.
* **New feature**: The new setting `REFRESH_TOKEN_GRACE_PERIOD_SECONDS` controls a grace period during which
  refresh tokens may be re-used.
* An `app_authorized` signal is fired when a token is generated.

### 1.0.0 [2017-06-07]

* **New feature**: AccessToken, RefreshToken and Grant models are now swappable.
* #477: **New feature**: Add support for RFC 7662 (IntrospectTokenView, introspect scope)
* **Compatibility**: Django 1.10 is the new minimum required version
* **Compatibility**: Django 1.11 is now supported
* **Backwards-incompatible**: The `oauth2_provider.ext.rest_framework` module
  has been moved to `oauth2_provider.contrib.rest_framework`
* #177: Changed `id` field on Application, AccessToken, RefreshToken and Grant to BigAutoField (bigint/bigserial)
* #321: Added `created` and `updated` auto fields to Application, AccessToken, RefreshToken and Grant
* #476: Disallow empty redirect URIs
* Fixed bad `url` parameter in some error responses.
* Django 2.0 compatibility fixes.
* The dependency on django-braces has been dropped.
* The oauthlib dependency is no longer pinned.

### 0.12.0 [2017-02-24]

* **New feature**: Class-based scopes backends. Listing scopes, available scopes and default scopes
  is now done through the class that the `SCOPES_BACKEND_CLASS` setting points to.
  By default, this is set to `oauth2_provider.scopes.SettingsScopes` which implements the
  legacy settings-based scope behaviour. No changes are necessary.
* **Dropped support for Python 3.2 and Python 3.3**, added support for Python 3.6
* Support for the `scopes` query parameter, deprecated in 0.6.1, has been dropped
* #448: Added support for customizing applications' allowed grant types
* #141: The `is_usable(request)` method on the Application model can be overridden to dynamically
  enable or disable applications.
* #434: Relax URL patterns to allow for UUID primary keys


### 0.11.0 [2016-12-1]

* #315: AuthorizationView does not overwrite requests on get
* #425: Added support for Django 1.10
* #396: added an IsAuthenticatedOrTokenHasScope Permission
* #357: Support multiple-user clients by allowing User to be NULL for Applications
* #389: Reuse refresh tokens if enabled.


### 0.10.0 [2015-12-14]

* **#322: dropping support for python 2.6 and django 1.4, 1.5, 1.6**
* #310: Fixed error that could occur sometimes when checking validity of incomplete AccessToken/Grant
* #333: Added possibility to specify the default list of scopes returned when scope parameter is missing
* #325: Added management views of issued tokens
* #249: Added a command to clean expired tokens
* #323: Application registration view uses custom application model in form class
* #299: `server_class` is now pluggable through Django settings
* #309: Add the py35-django19 env to travis
* #308: Use compact syntax for tox envs
* #306: Django 1.9 compatibility
* #288: Put additional information when generating token responses
* #297: Fixed doc about SessionAuthenticationMiddleware
* #273: Generic read write scope by resource


### 0.9.0 [2015-07-28]

* ``oauthlib_backend_class`` is now pluggable through Django settings
* #127: ``application/json`` Content-Type is now supported using ``JSONOAuthLibCore``
* #238: Fixed redirect uri handling in case of error
* #229: Invalidate access tokens when getting a new refresh token
* added support for oauthlib 1.0


### 0.8.2 [2015-06-25]

* Fix the migrations to be two-step and allow upgrade from 0.7.2

### 0.8.1 [2015-04-27]

* South migrations fixed. Added new django migrations.

### 0.8.0 [2015-03-27]

* Several docs improvements and minor fixes
* #185: fixed vulnerabilities on Basic authentication
* #173: ProtectResourceMixin now allows OPTIONS requests
* Fixed `client_id` and `client_secret` characters set
* #169: hide sensitive informations in error emails
* #161: extend search to all token types when revoking a token
* #160: return empty response on successful token revocation
* #157: skip authorization form with ``skip_authorization_completely`` class field
* #155: allow custom uri schemes
* fixed ``get_application_model`` on Django 1.7
* fixed non rotating refresh tokens
* #137: fixed base template
* customized ``client_secret`` length
* #38: create access tokens not bound to a user instance for *client credentials* flow


### 0.7.2 [2014-07-02]

* Don't pin oauthlib

### 0.7.1 [2014-04-27]

* Added database indexes to the OAuth2 related models to improve performances.

**Warning: schema migration does not work for sqlite3 database, migration should be performed manually**

### 0.7.0 [2014-03-01]

* Created a setting for the default value for approval prompt.
* Improved docs
* Don't pin django-braces and six versions

**Backwards incompatible changes in 0.7.0**

* Make Application model truly "swappable" (introduces a new non-namespaced setting `OAUTH2_PROVIDER_APPLICATION_MODEL`)


### 0.6.1 [2014-02-05]

* added support for `scope` query parameter keeping backwards compatibility for the original `scopes` parameter.
* __str__ method in Application model returns content of `name` field when available

### 0.6.0 [2014-01-26]

* oauthlib 0.6.1 support
* Django dev branch support
* Python 2.6 support
* Skip authorization form via `approval_prompt` parameter

**Bugfixes**

* Several fixes to the docs
* Issue #71: Fix migrations
* Issue #65: Use OAuth2 password grant with multiple devices
* Issue #84: Add information about login template to tutorial.
* Issue #64: Fix urlencode clientid secret


### 0.5.0 [2013-09-17]

* oauthlib 0.6.0 support

**Backwards incompatible changes in 0.5.0**

* `backends.py` module has been renamed to `oauth2_backends.py` so you should change your imports whether
  you're extending this module

**Bugfixes**

* Issue #54: Auth backend proposal to address #50
* Issue #61: Fix contributing page
* Issue #55: Add support for authenticating confidential client with request body params
* Issue #53: Quote characters in the url query that are safe for Django but not for oauthlib


### 0.4.1 [2013-09-06]

* Optimize queries on access token validation

### 0.4.0 [2013-08-09]

**New Features**

* Add Application management views, you no more need the admin to register, update and delete your application.
* Add support to configurable application model
* Add support for function based views

**Backwards incompatible changes in 0.4.0**

* `SCOPE` attribute in settings is now a dictionary to store `{'scope_name': 'scope_description'}`
* Namespace `oauth2_provider` is mandatory in urls. See issue #36

**Bugfixes**

* Issue #25: Bug in the Basic Auth parsing in Oauth2RequestValidator
* Issue #24: Avoid generation of `client_id` with ":" colon char when using HTTP Basic Auth
* Issue #21: IndexError when trying to authorize an application
* Issue #9: `default_redirect_uri` is mandatory when `grant_type` is implicit, `authorization_code` or all-in-one
* Issue #22: Scopes need a verbose description
* Issue #33: Add django-oauth-toolkit version on example main page
* Issue #36: Add mandatory namespace to urls
* Issue #31: Add docstring to OAuthToolkitError and FatalClientError
* Issue #32: Add docstring to `validate_uris`
* Issue #34: Documentation tutorial part1 needs corsheaders explanation
* Issue #36: Add mandatory namespace to urls
* Issue #45: Add docs for AbstractApplication
* Issue #47: Add docs for views decorators


### 0.3.2 [2013-07-10]

* Bugfix #37: Error in migrations with custom user on Django 1.5

### 0.3.1 [2013-07-10]

* Bugfix #27: OAuthlib refresh token refactoring

### 0.3.0 [2013-06-14]

* [Django REST Framework](http://django-rest-framework.org/) integration layer
* Bugfix #13: Populate request with client and user in `validate_bearer_token`
* Bugfix #12: Fix paths in documentation

**Backwards incompatible changes in 0.3.0**

* `requested_scopes` parameter in ScopedResourceMixin changed to `required_scopes`


### 0.2.1 [2013-06-06]

* Core optimizations

### 0.2.0 [2013-06-05]

* Add support for Django1.4 and Django1.6
* Add support for Python 3.3
* Add a default ReadWriteScoped view
* Add tutorial to docs


### 0.1.0 [2013-05-31]

* Support OAuth2 Authorization Flows


### 0.0.0 [2013-05-17]

* Discussion with Daniel Greenfeld at Django Circus
* Ignition
