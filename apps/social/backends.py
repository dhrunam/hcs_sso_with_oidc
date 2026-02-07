# apps/social/backends.py
"""
Custom social authentication backends for the application.
Extends social-auth-core backends with additional functionality
and integration with our UserProfile model.
"""

import logging
from typing import Dict, Any
from django.conf import settings
from django.contrib.auth import get_user_model
from social_core.backends.google import GoogleOAuth2
from social_core.backends.facebook import FacebookOAuth2
from social_core.backends.github import GithubOAuth2
from social_core.backends.microsoft import MicrosoftOAuth2
from social_core.backends.linkedin import  LinkedinOAuth2
from social_core.exceptions import AuthForbidden
from apps.core.models import UserProfile

# Try to import OIDC backends - they should be available in your version
try:
    # In social-auth-core 4.8.3, OIDC backends are available
    from social_core.backends.azuread import AzureADOAuth2
    from social_core.backends.okta import OktaOAuth2
    from social_core.backends.open_id_connect import OpenIdConnectAuth
    OIDC_AVAILABLE = True
except ImportError:
    OIDC_AVAILABLE = False
    # Create placeholder classes
    class AzureADOAuth2:
        pass
    
    class OktaOAuth2:
        pass
    
    class OpenIdConnectAuth:
        pass

logger = logging.getLogger(__name__)
User = get_user_model()


class BaseCustomBackend:
    """Base class for all custom social backends"""
    
    def get_identity_provider(self) -> str:
        """Get identity provider name for UserProfile"""
        # Clean up backend name for storage
        name = self.name
        for suffix in ['-oauth2', '-graph', '-oidc', '-openidconnect']:
            name = name.replace(suffix, '')
        return name
    
    def update_user_profile(self, user: User, response: Dict[str, Any]) -> UserProfile:
        """
        Update or create UserProfile for the authenticated user
        """
        try:
            # Determine external ID based on provider response
            external_id = None
            if response.get('sub'):  # OIDC standard
                external_id = response['sub']
            elif response.get('id'):  # Most social providers
                external_id = str(response['id'])
            elif hasattr(user, 'id'):
                external_id = str(user.id)
            
            profile, created = UserProfile.objects.update_or_create(
                user=user,
                defaults={
                    'identity_provider': self.get_identity_provider(),
                    'external_id': external_id,
                    'email_verified': response.get('email_verified', False),
                }
            )
            
            # Update additional fields if available
            update_fields = []
            
            if response.get('locale'):
                profile.preferred_language = response.get('locale')[:10]
                update_fields.append('preferred_language')
            
            if response.get('timezone') or response.get('zoneinfo'):
                profile.timezone = response.get('timezone') or response.get('zoneinfo')
                update_fields.append('timezone')
            
            # Update name fields from response
            if response.get('given_name') and not profile.user.first_name:
                profile.user.first_name = response.get('given_name')[:30]
                profile.user.save(update_fields=['first_name'])
            
            if response.get('family_name') and not profile.user.last_name:
                profile.user.last_name = response.get('family_name')[:30]
                profile.user.save(update_fields=['last_name'])
            
            if update_fields:
                profile.save(update_fields=update_fields)
            
            action = "created" if created else "updated"
            logger.info(f"UserProfile {action} for user {user.id} via {self.get_identity_provider()}")
            
            return profile
            
        except Exception as e:
            logger.error(f"Failed to update UserProfile: {e}")
            # Don't raise, just log - authentication should still proceed
            return None
    
    def validate_email_domain(self, email: str) -> bool:
        """Validate email domain against allowed domains"""
        if not email:
            return False
        
        allowed_domains = getattr(settings, 'SOCIAL_AUTH_ALLOWED_DOMAINS', [])
        if not allowed_domains:
            return True
        
        domain = email.split('@')[-1].lower() if '@' in email else ''
        
        if domain not in allowed_domains:
            logger.warning(f"Email domain {domain} not allowed")
            return False
        
        return True


class CustomGoogleOAuth2(BaseCustomBackend, GoogleOAuth2):
    """Custom Google OAuth2 backend"""
    name = 'google-oauth2'
    
    def get_user_details(self, response: Dict[str, Any]) -> Dict[str, Any]:
        details = {
            'username': response.get('email', '').split('@')[0] if response.get('email') else '',
            'email': response.get('email', ''),
            'fullname': response.get('name', ''),
            'first_name': response.get('given_name', ''),
            'last_name': response.get('family_name', ''),
            'picture': response.get('picture', ''),
            'locale': response.get('locale', ''),
            'google_id': response.get('sub', ''),
            'email_verified': response.get('email_verified', False),
        }
        
        if not self.validate_email_domain(details['email']):
            raise AuthForbidden(self, "Email domain not allowed")
        
        logger.info(f"Google auth successful: {details['email']}")
        return details
    
    def extra_data(self, user, uid, response, details=None, *args, **kwargs):
        """Store additional Google-specific data"""
        data = super().extra_data(user, uid, response, details, *args, **kwargs)
        data.update({
            'google_id': response.get('sub'),
            'picture': response.get('picture'),
            'locale': response.get('locale'),
            'hd': response.get('hd'),  # Google Apps domain
        })
        return data


class CustomFacebookOAuth2(BaseCustomBackend, FacebookOAuth2):
    """Custom Facebook OAuth2 backend"""
    name = 'facebook'
    
    def get_user_details(self, response: Dict[str, Any]) -> Dict[str, Any]:
        details = {
            'username': response.get('email', '').split('@')[0] if response.get('email') else f"fb_{response.get('id', '')}",
            'email': response.get('email', ''),
            'fullname': response.get('name', ''),
            'first_name': response.get('first_name', ''),
            'last_name': response.get('last_name', ''),
            'facebook_id': response.get('id', ''),
        }
        
        if details['email'] and not self.validate_email_domain(details['email']):
            raise AuthForbidden(self, "Email domain not allowed")
        
        logger.info(f"Facebook auth successful: {details['email'] or details['facebook_id']}")
        return details
    
    EXTRA_DATA = [
        ('id', 'facebook_id'),
        ('name', 'fullname'),
        ('first_name', 'first_name'),
        ('last_name', 'last_name'),
        ('email', 'email'),
    ]


class CustomGitHubOAuth2(BaseCustomBackend, GithubOAuth2):
    """Custom GitHub OAuth2 backend"""
    name = 'github'
    
    def get_user_details(self, response: Dict[str, Any]) -> Dict[str, Any]:
        details = {
            'username': response.get('login', ''),
            'email': response.get('email', ''),
            'fullname': response.get('name', ''),
            'github_id': str(response.get('id', '')),
            'avatar_url': response.get('avatar_url', ''),
            'blog': response.get('blog', ''),
            'company': response.get('company', ''),
            'location': response.get('location', ''),
        }
        
        logger.info(f"GitHub auth successful: {details['username']}")
        return details


class CustomMicrosoftOAuth2(BaseCustomBackend, MicrosoftOAuth2):
    """Custom Microsoft OAuth2 backend"""
    name = 'microsoft-graph'
    
    def get_user_details(self, response: Dict[str, Any]) -> Dict[str, Any]:
        details = {
            'username': response.get('userPrincipalName', '').split('@')[0] if response.get('userPrincipalName') else '',
            'email': response.get('mail') or response.get('userPrincipalName', ''),
            'fullname': response.get('displayName', ''),
            'first_name': response.get('givenName', ''),
            'last_name': response.get('surname', ''),
            'microsoft_id': response.get('id', ''),
            'job_title': response.get('jobTitle', ''),
            'office_location': response.get('officeLocation', ''),
        }
        
        if details['email'] and not self.validate_email_domain(details['email']):
            raise AuthForbidden(self, "Email domain not allowed")
        
        logger.info(f"Microsoft auth successful: {details['email']}")
        return details


class CustomLinkedinOAuth2(BaseCustomBackend, LinkedinOAuth2):
    """Custom LinkedIn OAuth2 backend"""
    name = 'linkedin'
    
    def get_user_details(self, response: Dict[str, Any]) -> Dict[str, Any]:
        email = response.get('email-address', '')
        details = {
            'username': f"li_{response.get('id', '')}",
            'email': email,
            'fullname': f"{response.get('firstName', '')} {response.get('lastName', '')}".strip(),
            'first_name': response.get('firstName', ''),
            'last_name': response.get('lastName', ''),
            'linkedin_id': response.get('id', ''),
            'headline': response.get('headline', ''),
            'industry': response.get('industry', ''),
            'picture_url': response.get('pictureUrl', ''),
        }
        
        logger.info(f"LinkedIn auth successful: {details['email'] or details['linkedin_id']}")
        return details


# OIDC-based backends (should work with your setup)
if OIDC_AVAILABLE:
    class CustomAzureADOAuth2(BaseCustomBackend, AzureADOAuth2):
        """Custom Azure AD OAuth2 backend"""
        name = 'azuread-oauth2'
        
        def get_user_details(self, response: Dict[str, Any]) -> Dict[str, Any]:
            details = {
                'username': response.get('preferred_username', '').split('@')[0] if response.get('preferred_username') else '',
                'email': response.get('email') or response.get('preferred_username', ''),
                'fullname': response.get('name', ''),
                'first_name': response.get('given_name', ''),
                'last_name': response.get('family_name', ''),
                'azuread_id': response.get('oid', '') or response.get('sub', ''),
                'email_verified': response.get('email_verified', False),
            }
            
            if details['email'] and not self.validate_email_domain(details['email']):
                raise AuthForbidden(self, "Email domain not allowed")
            
            logger.info(f"Azure AD auth successful: {details['email']}")
            return details
    
    class CustomOktaOAuth2(BaseCustomBackend, OktaOAuth2):
        """Custom Okta OAuth2 backend"""
        name = 'okta-oauth2'
        
        def get_user_details(self, response: Dict[str, Any]) -> Dict[str, Any]:
            details = {
                'username': response.get('preferred_username', ''),
                'email': response.get('email', ''),
                'fullname': response.get('name', ''),
                'first_name': response.get('given_name', ''),
                'last_name': response.get('family_name', ''),
                'okta_id': response.get('sub', ''),
                'email_verified': response.get('email_verified', False),
            }
            
            if not self.validate_email_domain(details['email']):
                raise AuthForbidden(self, "Email domain not allowed")
            
            logger.info(f"Okta auth successful: {details['email']}")
            return details
    
    class CustomOpenIdConnect(BaseCustomBackend, OpenIdConnectAuth):
        """Generic OpenID Connect backend"""
        name = 'openid-connect'
        
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # You can configure OIDC provider via settings
            self.OIDC_ENDPOINT = getattr(settings, 'SOCIAL_AUTH_OIDC_ENDPOINT', '')
        
        def get_user_details(self, response: Dict[str, Any]) -> Dict[str, Any]:
            details = {
                'username': response.get('preferred_username') or response.get('email', '').split('@')[0] or response.get('sub', ''),
                'email': response.get('email', ''),
                'fullname': response.get('name', ''),
                'first_name': response.get('given_name', ''),
                'last_name': response.get('family_name', ''),
                'oidc_id': response.get('sub', ''),
                'email_verified': response.get('email_verified', False),
                'picture': response.get('picture', ''),
                'locale': response.get('locale', ''),
                'zoneinfo': response.get('zoneinfo', ''),
            }
            
            if details['email'] and not self.validate_email_domain(details['email']):
                raise AuthForbidden(self, "Email domain not allowed")
            
            logger.info(f"OpenID Connect auth successful: {details['email']}")
            return details


# Simple function to get available backends
def get_available_backends():
    """Get dictionary of available social auth backends"""
    backends = {
        'google-oauth2': CustomGoogleOAuth2,
        'facebook': CustomFacebookOAuth2,
        'github': CustomGitHubOAuth2,
        'microsoft-graph': CustomMicrosoftOAuth2,
        'linkedin': CustomLinkedinOAuth2,
    }
    
    # Add OIDC backends if available
    if OIDC_AVAILABLE:
        backends.update({
            'azuread-oauth2': CustomAzureADOAuth2,
            'okta-oauth2': CustomOktaOAuth2,
            'openid-connect': CustomOpenIdConnect,
        })
    
    return backends