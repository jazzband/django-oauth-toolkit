from django.contrib import admin

from .models import Grant, AccessToken, RefreshToken, get_application_model


class ApplicationAdmin(admin.ModelAdmin):
    list_display = ("name", "user", "client_type", "authorization_grant_type")
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
    raw_id_fields = ("user", )


class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ("token", "user", "application")
    raw_id_fields = ("user", "access_token")


Application = get_application_model()

admin.site.register(Application, ApplicationAdmin)
admin.site.register(Grant, GrantAdmin)
admin.site.register(AccessToken, AccessTokenAdmin)
admin.site.register(RefreshToken, RefreshTokenAdmin)
