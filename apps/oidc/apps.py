from django.apps import AppConfig

class OIDCConfig(AppConfig):
    name = 'apps.oidc'
    verbose_name = 'OIDC Provider'
    
    def ready(self):
        # Import signal handlers
        import apps.oidc.signals  # noqa