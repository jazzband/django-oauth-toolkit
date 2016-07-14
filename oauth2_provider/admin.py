from django.contrib import admin

from .models import (get_grant_model, get_access_token_model,
                     get_refresh_token_model, get_application_model)


class RawIDAdmin(admin.ModelAdmin):
    raw_id_fields = ('user',)

Application = get_application_model()
Grant = get_grant_model()
AccessToken = get_access_token_model()
RefreshToken = get_refersh_token_model()

admin.site.register(Application, RawIDAdmin)
admin.site.register(Grant, RawIDAdmin)
admin.site.register(AccessToken, RawIDAdmin)
admin.site.register(RefreshToken, RawIDAdmin)
