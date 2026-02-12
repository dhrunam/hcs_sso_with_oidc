# apps/social/apps.py
from django.apps import AppConfig
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class SocialConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.social'
    verbose_name = 'Social Authentication'
    
    def ready(self):
        """
        Initialize social authentication when app is ready
        """
        # Only run in main process, not in management commands
        import sys
        if 'manage.py' in sys.argv and 'runserver' not in sys.argv:
            return
        
        # Import signals
        try:
            import apps.social.signals
            logger.debug("Social auth signals imported")
        except ImportError as e:
            logger.warning(f"Could not import social auth signals: {e}")
        
        # Validate configuration
        self.validate_configuration()
        
        # Register custom backends
        self.register_custom_backends()
        
        # Log initialization
        self.log_initialization()
        
        logger.info("✅ Social authentication app initialized successfully")
    
    def validate_configuration(self):
        """Validate required social auth configuration"""
        required_settings = [
            'SOCIAL_AUTH_GOOGLE_OAUTH2_KEY',
            'SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET',
            'SOCIAL_AUTH_FACEBOOK_KEY',
            'SOCIAL_AUTH_FACEBOOK_SECRET',
        ]
        
        missing_settings = []
        for setting in required_settings:
            if not getattr(settings, setting, None):
                missing_settings.append(setting)
        
        if missing_settings:
            logger.warning(
                f"Missing social auth settings: {', '.join(missing_settings)}. "
                "Some social providers may not work."
            )
        
        # Check if social auth is in INSTALLED_APPS
        if 'social_django' not in settings.INSTALLED_APPS:
            logger.error(
                "'social_django' not in INSTALLED_APPS. "
                "Social authentication will not work."
            )
        
        # Check if authentication backends are configured
        if 'social_core.backends.google.GoogleOAuth2' not in settings.AUTHENTICATION_BACKENDS:
            logger.warning(
                "Google OAuth2 backend not in AUTHENTICATION_BACKENDS. "
                "Google login may not work."
            )
    
    def register_custom_backends(self):
        """Register custom social auth backends"""
        try:
            from social_core import backends as BACKENDS
            from apps.social.backends import (
                CustomGoogleOAuth2,
                CustomFacebookOAuth2
            )
            
            # Define custom backends to register
            custom_backends = {
                'google-oauth2': CustomGoogleOAuth2,
                'facebook': CustomFacebookOAuth2
               
            }
            
            registered_count = 0
            for name, backend in custom_backends.items():
                if name not in BACKENDS:
                    BACKENDS[name] = backend
                    registered_count += 1
                    logger.debug(f"Registered custom backend: {name}")
            
            if registered_count > 0:
                logger.info(f"✅ Registered {registered_count} custom social auth backends")
            
        except ImportError as e:
            logger.error(f"Failed to import social_core: {e}. Make sure 'social_django' is installed.")
        except Exception as e:
            logger.error(f"Failed to register custom backends: {e}")
    
    def log_initialization(self):
        """Log social auth initialization details"""
        try:
            from social_core import backends as BACKENDS
            
            # Get enabled providers from settings
            enabled_providers = []
            if getattr(settings, 'SOCIAL_AUTH_GOOGLE_OAUTH2_KEY', None):
                enabled_providers.append('Google')
            if getattr(settings, 'SOCIAL_AUTH_FACEBOOK_KEY', None):
                enabled_providers.append('Facebook')
            if getattr(settings, 'SOCIAL_AUTH_MICROSOFT_KEY', None):
                enabled_providers.append('Microsoft')
            if getattr(settings, 'SOCIAL_AUTH_GITHUB_KEY', None):
                enabled_providers.append('GitHub')
            
            logger.info(
                # f"Social auth initialized with {len(BACKENDS)} backends. "
                f"Enabled providers: {', '.join(enabled_providers) if enabled_providers else 'None'}"
            )
            
        except ImportError:
            pass
    
    def get_social_providers(self):
        """
        Get list of configured social providers
        Can be used in templates or APIs
        """
        providers = []
        
        # Google
        if getattr(settings, 'SOCIAL_AUTH_GOOGLE_OAUTH2_KEY', None):
            providers.append({
                'id': 'google',
                'name': 'Google',
                'login_url': '/api/social/login/google-oauth2/',
                'scope': 'openid email profile',
            })
        
        # Facebook
        if getattr(settings, 'SOCIAL_AUTH_FACEBOOK_KEY', None):
            providers.append({
                'id': 'facebook',
                'name': 'Facebook',
                'login_url': '/api/social/login/facebook/',
                'scope': 'email',
            })
        
        # Microsoft
        if getattr(settings, 'SOCIAL_AUTH_MICROSOFT_KEY', None):
            providers.append({
                'id': 'microsoft',
                'name': 'Microsoft',
                'login_url': '/api/social/login/microsoft-graph/',
                'scope': 'User.Read',
            })
        
        # GitHub
        if getattr(settings, 'SOCIAL_AUTH_GITHUB_KEY', None):
            providers.append({
                'id': 'github',
                'name': 'GitHub',
                'login_url': '/api/social/login/github/',
                'scope': 'user:email',
            })
        
        return providers