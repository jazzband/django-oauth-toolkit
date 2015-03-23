Permissions
===========

Django OAuth Toolkit provides a few utility classes to use along with other permissions in Django REST Framework,
so you can easily add scoped-based permission checks to your API views.

More details on how to add custom permissions to your API Endpoints can be found at the official
`Django REST Framework documentation <http://www.django-rest-framework.org/api-guide/permissions/>`_


TokenHasScope
-------------

The `TokenHasScope` permission class will allow the access only when the current access token has been
authorized for all the scopes listed in the `required_scopes` field of the view.

For example:

.. code-block:: python

    class SongView(views.APIView):
        authentication_classes = [OAuth2Authentication]
        permission_classes = [TokenHasScope]
        required_scopes = ['music']

The `required_scopes` attribute is mandatory.


TokenHasReadWriteScope
----------------------

TODO: add docs for TokenHasReadWriteScope permission class with usage examples

