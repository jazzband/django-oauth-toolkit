from django.contrib import admin

from .models import (
    get_access_token_model, get_application_model,
    get_grant_model, get_refresh_token_model
)


class ApplicationAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "user", "client_type", "authorization_grant_type")
    list_filter = ("client_type", "authorization_grant_type", "skip_authorization")
    radio_fields = {
        "client_type": admin.HORIZONTAL,
        "authorization_grant_type": admin.VERTICAL,
    }
    raw_id_fields = ("user", )


class GrantAdmin(admin.ModelAdmin):
    list_display = ("code", "application", "user", "expires")
    raw_id_fields = ("user", )


class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ("token", "user", "application", "expires")
    raw_id_fields = ("user", "source_refresh_token")


class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ("token", "user", "application")
    raw_id_fields = ("user", "access_token")


Application = get_application_model()
Grant = get_grant_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()

admin.site.register(Application, ApplicationAdmin)
admin.site.register(Grant, GrantAdmin)
admin.site.register(AccessToken, AccessTokenAdmin)
admin.site.register(RefreshToken, RefreshTokenAdmin)
