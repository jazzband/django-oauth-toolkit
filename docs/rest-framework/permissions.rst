Permissions
===========

Django OAuth Toolkit provides a few utility classes to use along with other permissions in Django REST Framework,
so you can easily add scoped-based permission checks to your API views.

More details on how to add custom permissions to your API Endpoints can be found at the official
`Django REST Framework documentation <http://www.django-rest-framework.org/api-guide/permissions/>`_


TokenHasScope
-------------

The `TokenHasScope` permission class allows the access only when the current access token has been
authorized for **all** the scopes listed in the `required_scopes` field of the view.

For example:

.. code-block:: python

    class SongView(views.APIView):
        authentication_classes = [OAuth2Authentication]
        permission_classes = [TokenHasScope]
        required_scopes = ['music']

The `required_scopes` attribute is mandatory.


TokenHasReadWriteScope
----------------------

The `TokenHasReadWriteScope` permission class allows the access based on the `READ_SCOPE` and `WRITE_SCOPE` configured in the settings.

When the current request's method is one of the "safe" methods `GET`, `HEAD`, `OPTIONS`
the access is allowed only if the access token has been authorized for the `READ_SCOPE` scope.
When the request's method is one of `POST`, `PUT`, `PATCH`, `DELETE` the access is allowed if the access token has been authorized for the `WRITE_SCOPE`.

The `required_scopes` attribute is optional and can be used to other scopes needed by the view.

For example:

.. code-block:: python

    class SongView(views.APIView):
        authentication_classes = [OAuth2Authentication]
        permission_classes = [TokenHasReadWriteScope]
        required_scopes = ['music']

When a request is performed both the `READ_SCOPE` \\ `WRITE_SCOPE` and 'music' scopes are required to be authorized for the current access token.


TokenHasResourceScope
----------------------
The `TokenHasResourceScope` permission class allows the access only when the current access token has been authorized for **all** the scopes listed in the `required_scopes` field of the view but according of request's method.

When the current request's method is one of the "safe" methods, the access is allowed only if the access token has been authorized for the `scope:read` scope (for example `music:read`).
When the request's method is one of "non safe" methods, the access is allowed only if the access token has been authorizes for the `scope:write` scope (for example `music:write`).

.. code-block:: python

    class SongView(views.APIView):
        authentication_classes = [OAuth2Authentication]
        permission_classes = [TokenHasResourceScope]
        required_scopes = ['music']

The `required_scopes` attribute is mandatory (you just need inform the resource scope).


IsAuthenticatedOrTokenHasScope
------------------------------
The `TokenHasResourceScope` permission class allows the access only when the current access token has been authorized for **all** the scopes listed in the `required_scopes` field of the view but according of request's method.
And also allows access to Authenticated users who are authenticated in django, but were not authenticated trought the OAuth2Authentication class.
This allows for protection of the api using scopes, but still let's users browse the full browseable API.
To restrict users to only browse the parts of the browseable API they should be allowed to see, you can combine this with the DjangoModelPermission or the DjangoObjectPermission.

For example:

.. code-block:: python

    class SongView(views.APIView):
        permission_classes = [IsAuthenticatedOrTokenHasScope, DjangoModelPermission]
        required_scopes = ['music']

The `required_scopes` attribute is mandatory.


TokenHasMethodScope
-------------------

The `TokenHasMethodScope` permission class allows the access based on a per-method map.

The `required_scopes_map` attribute is a required map of methods and required scopes for each method.

For example:

.. code-block:: python

    class SongView(views.APIView):
        authentication_classes = [OAuth2Authentication]
        permission_classes = [TokenHasMethodScope]
        required_scopes_map = {
            "GET": ["read"],
            "POST": ["create"],
            "PUT": ["update", "put"],
            "DELETE": ["delete"],
        }

When a `GET` request is performed the 'read' scope is required to be authorized
for the current access token. When a `PUT` is performed, 'update' and 'put' are required
and when a `DELETE` is performed, the 'delete' scope is required.

TokenHasMethodPathScope
-----------------------

The `TokenHasMethodPathScope` permission class allows the access based on a per-method and resource regex
map and allows for alternative lists of required scopes. This permission provides full functionality
required by REST API specifications like the
`OpenAPI Specification's security requirement object <https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.0.md#securityRequirementObject>`_.

The `required_scopes_map_list` attribute is a required list of `RequiredMethodScopes` instances.

For example:

.. code-block:: python

    class SongView(views.APIView):
        authentication_classes = [OAuth2Authentication]
        permission_classes = [TokenHasMethodPathScope]
        required_scopes_map_list = [
            RequiredMethodScopes("GET", r"^/widgets/?[^/]*/?$", ["read", "get widget"]),
            RequiredMethodScopes("POST", r"^/widgets/?$", ["create", "post widget"]),
            RequiredMethodScopes("PUT", r"^/widgets/[^/]+/?$", ["update", "put widget"]),
            RequiredMethodScopes("DELETE", r"^/widgets/[^/]+/?$", ["delete", "scope2 scope3"]),
            RequiredMethodScopes("GET", r"^/gadgets/?[^/]*/?$", ["read gadget", "get scope1"]),
            RequiredMethodScopes("POST", r"^/gadgets/?$", ["create scope1", "post scope2"]),
            RequiredMethodScopes("PUT", r"^/gadgets/[^/]+/?$", ["update scope2 scope3", "put gadget"]),
            RequiredMethodScopes("DELETE", r"^/gadgets/[^/]+/?$", ["delete scope1", "scope2 scope3"]),
        ]

For each listed method and the regex resource path, any matching list of possible alternative required scopes is required to succeed. For the above example, `GET /widgets/1234` will be permitted if either
'read' _or_ 'get' and  'widget' scopes are authorized. `POST /gadgets/` will be permitted if 'create' and
'scope1' _or_ 'post' and 'scope2' are authorized.
