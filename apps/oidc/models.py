from django.db import models
from django.conf import settings


class OAuthApplicationExtension(models.Model):
    """
    Per-application metadata that extends oauth2_provider.Application without
    swapping the APPLICATION_MODEL (preserves existing data and FK relations).

    is_trusted_resource_server
        When True the application is allowed to call the introspection endpoint
        and validate tokens that were originally issued to *other* clients.
        This is the standard OAuth2/RFC-7662 "resource server" pattern.

        Example: hcs_cms_api must introspect tokens issued to hcs_cms_ui.
    """

    application = models.OneToOneField(
        'oauth2_provider.Application',
        on_delete=models.CASCADE,
        related_name='extension',
        verbose_name='OAuth application',
    )
    is_trusted_resource_server = models.BooleanField(
        default=False,
        help_text=(
            'Allow this client to introspect tokens issued to any other '
            'registered client (resource-server role, RFC 7662).'
        ),
    )

    class Meta:
        verbose_name = 'Application extension'
        verbose_name_plural = 'Application extensions'

    def __str__(self):
        return f'{self.application.name} (extension)'
