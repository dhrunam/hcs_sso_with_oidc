from django.contrib import admin
from django.contrib.auth import get_user_model
from oauth2_provider.admin import ApplicationAdmin
from oauth2_provider.models import Application
from .models import OAuthApplicationExtension


class OAuthApplicationExtensionInline(admin.StackedInline):
    model = OAuthApplicationExtension
    can_delete = False
    verbose_name = 'Resource server settings'
    verbose_name_plural = 'Resource server settings'
    fields = ('is_trusted_resource_server',)


class ExtendedApplicationAdmin(ApplicationAdmin):
    """Extends the default ApplicationAdmin with the resource-server toggle."""
    inlines = ApplicationAdmin.inlines + (OAuthApplicationExtensionInline,)


# Re-register Application with the extended admin
admin.site.unregister(Application)
admin.site.register(Application, ExtendedApplicationAdmin)

admin.site.register(OAuthApplicationExtension)
