# apps/social/__init__.py
default_app_config = 'apps.social.apps.SocialConfig'

# Export social providers utility
from django.utils.module_loading import import_string
from django.conf import settings

def get_social_providers():
    """
    Helper function to get configured social providers
    """
    try:
        app_config = import_string('apps.social.apps.SocialConfig')
        return app_config.get_social_providers()
    except:
        return []

__all__ = ['get_social_providers']