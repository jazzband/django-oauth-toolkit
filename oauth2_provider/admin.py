from django.contrib import admin

from .models import Grant, AccessToken, RefreshToken, get_application_model


class RawIDAdmin(admin.ModelAdmin):
    raw_id_fields = ('user',)

Application = get_application_model()

admin.site.register(Application, RawIDAdmin)
admin.site.register(Grant, RawIDAdmin)
admin.site.register(AccessToken, RawIDAdmin)
admin.site.register(RefreshToken, RawIDAdmin)
