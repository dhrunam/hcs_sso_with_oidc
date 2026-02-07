# apps/oidc/validators.py
from oauth2_provider.oauth2_validators import OAuth2Validator
from django.contrib.auth.models import Group
from apps.core.models import UserProfile
from django.utils import timezone
import logging
from django.core.exceptions import ObjectDoesNotExist

logger = logging.getLogger(__name__)

class CustomOAuth2Validator(OAuth2Validator):
    """
    Custom validator to add OIDC claims
    """
    
    oidc_claims_supported = [
        'sub', 'name', 'given_name', 'family_name', 
        'preferred_username', 'email', 'email_verified',
        'picture', 'profile', 'phone_number', 'address',
        'organization', 'department', 'employee_id',
        'identity_provider', 'locale', 'zoneinfo'
    ]
    
    def _get_user_profile(self, user):
        """Helper method to get user profile with caching/optimization"""
        try:
            # Use select_related to optimize database queries
            return UserProfile.objects.select_related(
                'department__organization'
            ).get(user=user)
        except (UserProfile.DoesNotExist, ObjectDoesNotExist):
            logger.warning(f"No profile found for user {user.id}")
            return None
    
    def get_additional_claims(self, request):
        """Add custom claims to ID token"""
        user = request.user
        profile = self._get_user_profile(user)
        
        # Base claims
        claims = {
            'sub': str(user.id),
            'auth_time': int(timezone.now().timestamp()),
        }
        
        # Add claims based on scopes
        scopes = set(request.scopes)
        
        if 'profile' in scopes:
            claims.update({
                'name': f'{user.first_name} {user.last_name}'.strip() or user.username,
                'given_name': user.first_name,
                'family_name': user.last_name,
                'preferred_username': user.username,
                'updated_at': int(
                    (user.last_login if user.last_login else user.date_joined).timestamp()
                ),
            })
        
        if 'email' in scopes:
            claims.update({
                'email': user.email,
                'email_verified': profile.email_verified if profile else False,
            })
        
        # Always include identity provider
        claims['identity_provider'] = profile.identity_provider if profile else 'local'
        
        # Custom/org claims
        if any(scope in scopes for scope in ['custom', 'org', 'organizational']):
            if profile:
                if profile.department and profile.department.organization:
                    claims.update({
                        'organization': profile.department.organization.name,
                        'department': profile.department.code,
                    })
                
                if profile.employee_id:
                    claims['employee_id'] = profile.employee_id
                
                if profile.job_title:
                    claims['job_title'] = profile.job_title
        
        return claims
    
    def get_userinfo_claims(self, request):
        """Get claims for userinfo endpoint"""
        from apps.oidc.utils.claims import get_userinfo_claims as utils_get_userinfo_claims
        
        user = request.user
        scopes = set(request.scopes)
        
        return utils_get_userinfo_claims(user, scopes, request)
    
  
    def save_bearer_token(self, token, request, *args, **kwargs):
        """
        Save token with additional metadata
        """
        # Add identity provider info to token
        if hasattr(request, 'user') and request.user.is_authenticated:
            profile = self._get_user_profile(request.user)
            if profile:
                token['identity_provider'] = profile.identity_provider
                logger.info(f"Token issued for user {request.user.id} via {profile.identity_provider}")
        
        return super().save_bearer_token(token, request, *args, **kwargs)
    
    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """
        Return default scopes for this client
        """
        default_scopes = super().get_default_scopes(client_id, request, *args, **kwargs)
        
        # Add openid scope by default for OIDC
        if 'openid' not in default_scopes:
            default_scopes.append('openid')
        
        return default_scopes
    
    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """
        Validate requested scopes against allowed scopes
        """
        # Ensure openid scope is present for OIDC requests
        if 'openid' in scopes:
            # Add profile and email as default for OIDC
            if 'profile' not in scopes:
                scopes.append('profile')
            if 'email' not in scopes:
                scopes.append('email')
        
        return super().validate_scopes(client_id, scopes, client, request, *args, **kwargs)