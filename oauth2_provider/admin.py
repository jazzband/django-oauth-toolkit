from django.contrib import admin
from .models import Application, Grant, AccessToken, RefreshToken

admin.site.register(Application)
admin.site.register(Grant)
admin.site.register(AccessToken)
admin.site.register(RefreshToken)
