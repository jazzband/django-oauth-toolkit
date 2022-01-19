# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!--
## [unreleased]
### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security
  -->

## [Unreleased]

### Added
* #651 Batch expired token deletions in `cleartokens` management command
* Added pt-BR translations.
* #1070 Add a Celery task for clearing expired tokens, e.g. to be scheduled as a [periodic task](https://docs.celeryproject.org/en/stable/userguide/periodic-tasks.html)

### Fixed
* #1012 Return status for introspecting a nonexistent token from 401 to the correct value of 200 per [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662#section-2.2).

## [1.6.3] 2022-01-11

### Fixed
* #1085 Fix for #1083 admin UI search for idtoken results in `django.core.exceptions.FieldError: Cannot resolve keyword 'token' into field.`

### Added
* #1085 Add admin UI search fields for additional models.

## [1.6.2] 2022-01-06

**NOTE: This release reverts an inadvertently-added breaking change.**

### Fixed

* #1056 Add missing migration triggered by [Django 4.0 changes to the migrations autodetector](https://docs.djangoproject.com/en/4.0/releases/4.0/#migrations-autodetector-changes).
* #1068 Revert #967 which incorrectly changed an API. See #1066.

## [1.6.1] 2021-12-23

### Changed
* Note: Only Django 4.0.1+ is supported due to a regression in Django 4.0.0. [Explanation](https://github.com/jazzband/django-oauth-toolkit/pull/1046#issuecomment-998015272)

### Fixed
* Miscellaneous 1.6.0 packaging issues.

## [1.6.0] 2021-12-19
### Added
* #949 Provide django.contrib.auth.authenticate() with a `request` for compatibiity with more backends (like django-axes).
* #968, #1039 Add support for Django 3.2 and 4.0.
* #953 Allow loopback redirect URIs using random ports as described in [RFC8252 section 7.3](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3).
* #972 Add Farsi/fa language support.
* #978 OIDC: Add support for [rotating multiple RSA private keys](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#rotating-the-rsa-private-key).
* #978 OIDC: Add new [OIDC_JWKS_MAX_AGE_SECONDS](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#oidc-jwks-max-age-seconds) to improve `jwks_uri` caching.
* #967 OIDC: Add [additional claims](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#adding-claims-to-the-id-token) beyond `sub` to the id_token.
* #1041 Add a search field to the Admin UI (e.g. for search for tokens by email address).

### Changed
* #981 Require redirect_uri if multiple URIs are registered per [RFC6749 section 3.1.2.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3)
* #991 Update documentation of [REFRESH_TOKEN_EXPIRE_SECONDS](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#refresh-token-expire-seconds) to indicate it may be `int` or `datetime.timedelta`.
* #977 Update [Tutorial](https://django-oauth-toolkit.readthedocs.io/en/stable/tutorial/tutorial_01.html#) to show required `include`.

### Removed
* #968 Remove support for Django 3.0 & 3.1 and Python 3.6
* #1035 Removes default_app_config for Django Deprecation Warning
* #1023 six should be dropped

### Fixed
* #963 Fix handling invalid hex values in client query strings with a 400 error rather than 500.
* #973 [Tutorial](https://django-oauth-toolkit.readthedocs.io/en/latest/tutorial/tutorial_01.html#start-your-app) updated to use `django-cors-headers`.
* #956 OIDC: Update documentation of [get_userinfo_claims](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#adding-information-to-the-userinfo-service) to add the missing argument.


## [1.5.0] 2021-03-18

### Added
* #915 Add optional OpenID Connect support.

### Changed
* #942 Help via defunct Google group replaced with using GitHub issues

## [1.4.1] 2021-03-12

### Changed
* #925 OAuth2TokenMiddleware converted to new style middleware, and no longer extends MiddlewareMixin.

### Removed
* #936 Remove support for Python 3.5

## [1.4.0] 2021-02-08

### Added
* #917 Documentation improvement for Access Token expiration.
* #916 (for DOT contributors) Added `tox -e livedocs` which launches a local web server on `locahost:8000`
  to display Sphinx documentation with live updates as you edit.
* #891 (for DOT contributors) Added [details](https://django-oauth-toolkit.readthedocs.io/en/latest/contributing.html)
  on how best to contribute to this project.
* #884 Added support for Python 3.9
* #898 Added the ability to customize classes for django admin
* #690 Added pt-PT translations to HTML templates. This enables adding additional translations.

### Fixed
* #906 Made token revocation not apply a limit to the `select_for_update` statement (impacts Oracle 12c database).
* #903 Disable `redirect_uri` field length limit for `AbstractGrant`

## [1.3.3] 2020-10-16

### Added
* added `select_related` in intospect view for better query performance
* #831 Authorization token creation now can receive an expire date
* #831 Added a method to override Grant creation
* #825 Bump oauthlib to 3.1.0 to introduce PKCE
* Support for Django 3.1

### Fixed
* #847: Fix inappropriate message when response from authentication server is not OK.

### Changed
* few smaller improvements to remove older django version compatibility #830, #861, #862, #863

## [1.3.2] 2020-03-24

### Fixed
* Fixes: 1.3.1 inadvertently uploaded to pypi with an extra migration (0003...) from a dev branch.

## [1.3.1] 2020-03-23

### Added
* #725: HTTP Basic Auth support for introspection (Fix issue #709)

### Fixed
* #812: Reverts #643 pass wrong request object to authenticate function.
* Fix concurrency issue with refresh token requests (#[810](https://github.com/jazzband/django-oauth-toolkit/pull/810))
* #817: Reverts #734 tutorial documentation error.


## [1.3.0] 2020-03-02

### Added
* Add support for Python 3.7 & 3.8
* Add support for Django>=2.1,<3.1
* Add requirement for oauthlib>=3.0.1
* Add support for [Proof Key for Code Exchange (PKCE, RFC 7636)](https://tools.ietf.org/html/rfc7636).
* Add support for custom token generators (e.g. to create JWT tokens).
* Add new `OAUTH2_PROVIDER` [settings](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html):
  - `ACCESS_TOKEN_GENERATOR` to override the default access token generator.
  - `REFRESH_TOKEN_GENERATOR` to override the default refresh token generator.
  - `EXTRA_SERVER_KWARGS` options dictionary for oauthlib's Server class.
  - `PKCE_REQUIRED` to require PKCE.
* Add `createapplication` management command to create an application.
* Add `id` in toolkit admin console applications list.
* Add nonstandard Google support for [urn:ietf:wg:oauth:2.0:oob] `redirect_uri`
  for [Google OAuth2](https://developers.google.com/identity/protocols/OAuth2InstalledApp) "manual copy/paste".
  **N.B.** this feature appears to be deprecated and replaced with methods described in
  [RFC 8252: OAuth2 for Native Apps](https://tools.ietf.org/html/rfc8252) and *may* be deprecated and/or removed
  from a future release of Django-oauth-toolkit.

### Changed
* Change this change log to use [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.
* **Backwards-incompatible** squashed migrations:
  If you are currently on a release < 1.2.0, you will need to first install 1.2.0 then `manage.py migrate` before
  upgrading to >= 1.3.0.
* Improved the [tutorial](https://django-oauth-toolkit.readthedocs.io/en/latest/tutorial/tutorial.html).

### Removed
* Remove support for Python 3.4
* Remove support for Django<=2.0
* Remove requirement for oauthlib<3.0

### Fixed
* Fix a race condition in creation of AccessToken with external oauth2 server.
* Fix several concurrency issues. (#[638](https://github.com/jazzband/django-oauth-toolkit/issues/638))
* Fix to pass `request` to `django.contrib.auth.authenticate()` (#[636](https://github.com/jazzband/django-oauth-toolkit/issues/636))
* Fix missing `oauth2_error` property exception oauthlib_core.verify_request method raises exceptions in authenticate.
  (#[633](https://github.com/jazzband/django-oauth-toolkit/issues/633))
* Fix "django.db.utils.NotSupportedError: FOR UPDATE cannot be applied to the nullable side of an outer join" for postgresql.
  (#[714](https://github.com/jazzband/django-oauth-toolkit/issues/714))
* Fix to return a new refresh token during grace period rather than the recently-revoked one.
  (#[702](https://github.com/jazzband/django-oauth-toolkit/issues/702))
* Fix a bug in refresh token revocation.
  (#[625](https://github.com/jazzband/django-oauth-toolkit/issues/625))

## 1.2.0 [2018-06-03]

* **Compatibility**: Python 3.4 is the new minimum required version.
* **Compatibility**: Django 2.0 is the new minimum required version.
* **New feature**: Added TokenMatchesOASRequirements Permissions.
* validators.URIValidator has been updated to match URLValidator behaviour more closely.
* Moved `redirect_uris` validation to the application clean() method.


## 1.1.2 [2018-05-12]

* Return state with Authorization Denied error (RFC6749 section 4.1.2.1)
* Fix a crash with malformed base64 authentication headers
* Fix a crash with malformed IPv6 redirect URIs

## 1.1.1 [2018-05-08]

* **Critical**: Django OAuth Toolkit 1.1.0 contained a migration that would revoke all existing
  RefreshTokens (`0006_auto_20171214_2232`). This release corrects the migration.
  If you have already ran it in production, please see the following issue for more details:
  https://github.com/jazzband/django-oauth-toolkit/issues/589


## 1.1.0 [2018-04-13]

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

## 1.0.0 [2017-06-07]

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

## 0.12.0 [2017-02-24]

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


## 0.11.0 [2016-12-1]

* #315: AuthorizationView does not overwrite requests on get
* #425: Added support for Django 1.10
* #396: added an IsAuthenticatedOrTokenHasScope Permission
* #357: Support multiple-user clients by allowing User to be NULL for Applications
* #389: Reuse refresh tokens if enabled.


## 0.10.0 [2015-12-14]

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


## 0.9.0 [2015-07-28]

* ``oauthlib_backend_class`` is now pluggable through Django settings
* #127: ``application/json`` Content-Type is now supported using ``JSONOAuthLibCore``
* #238: Fixed redirect uri handling in case of error
* #229: Invalidate access tokens when getting a new refresh token
* added support for oauthlib 1.0


## 0.8.2 [2015-06-25]

* Fix the migrations to be two-step and allow upgrade from 0.7.2

## 0.8.1 [2015-04-27]

* South migrations fixed. Added new django migrations.

## 0.8.0 [2015-03-27]

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


## 0.7.2 [2014-07-02]

* Don't pin oauthlib

## 0.7.1 [2014-04-27]

* Added database indexes to the OAuth2 related models to improve performances.

**Warning: schema migration does not work for sqlite3 database, migration should be performed manually**

## 0.7.0 [2014-03-01]

* Created a setting for the default value for approval prompt.
* Improved docs
* Don't pin django-braces and six versions

**Backwards incompatible changes in 0.7.0**

* Make Application model truly "swappable" (introduces a new non-namespaced setting `OAUTH2_PROVIDER_APPLICATION_MODEL`)


## 0.6.1 [2014-02-05]

* added support for `scope` query parameter keeping backwards compatibility for the original `scopes` parameter.
* __str__ method in Application model returns content of `name` field when available

## 0.6.0 [2014-01-26]

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


## 0.5.0 [2013-09-17]

* oauthlib 0.6.0 support

**Backwards incompatible changes in 0.5.0**

* `backends.py` module has been renamed to `oauth2_backends.py` so you should change your imports whether
  you're extending this module

**Bugfixes**

* Issue #54: Auth backend proposal to address #50
* Issue #61: Fix contributing page
* Issue #55: Add support for authenticating confidential client with request body params
* Issue #53: Quote characters in the url query that are safe for Django but not for oauthlib


## 0.4.1 [2013-09-06]

* Optimize queries on access token validation

## 0.4.0 [2013-08-09]

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


## 0.3.2 [2013-07-10]

* Bugfix #37: Error in migrations with custom user on Django 1.5

## 0.3.1 [2013-07-10]

* Bugfix #27: OAuthlib refresh token refactoring

## 0.3.0 [2013-06-14]

* [Django REST Framework](http://django-rest-framework.org/) integration layer
* Bugfix #13: Populate request with client and user in `validate_bearer_token`
* Bugfix #12: Fix paths in documentation

**Backwards incompatible changes in 0.3.0**

* `requested_scopes` parameter in ScopedResourceMixin changed to `required_scopes`


## 0.2.1 [2013-06-06]

* Core optimizations

## 0.2.0 [2013-06-05]

* Add support for Django1.4 and Django1.6
* Add support for Python 3.3
* Add a default ReadWriteScoped view
* Add tutorial to docs


## 0.1.0 [2013-05-31]

* Support OAuth2 Authorization Flows


## 0.0.0 [2013-05-17]

* Discussion with Daniel Greenfeld at Django Circus
* Ignition
