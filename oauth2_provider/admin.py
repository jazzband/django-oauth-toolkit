from django.contrib import admin
from .models import ApplicationInstallation, Grant, AccessToken, RefreshToken, get_application_model

Application = get_application_model()

admin.site.register(Application)
admin.site.register(ApplicationInstallation)
admin.site.register(Grant)
admin.site.register(AccessToken)
admin.site.register(RefreshToken)
