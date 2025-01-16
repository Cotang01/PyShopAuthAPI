from django.contrib import admin
from .models import AuthUser, RefreshToken


@admin.register(AuthUser)
class AuthUserAdmin(admin.ModelAdmin):
    pass


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    pass
