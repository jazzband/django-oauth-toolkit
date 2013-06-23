from django.contrib import admin
from .models import Grant, AccessToken, RefreshToken, get_application_model

Application = get_application_model()

admin.site.register(Application)
admin.site.register(Grant)
admin.site.register(AccessToken)
admin.site.register(RefreshToken)
