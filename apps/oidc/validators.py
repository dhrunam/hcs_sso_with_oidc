# apps/oidc/validators.py
from oauth2_provider.oauth2_validators import OAuth2Validator
from django.contrib.auth.models import Group
from apps.core.models import UserProfile
from django.utils import timezone
import logging
from django.core.exceptions import ObjectDoesNotExist

logger = logging.getLogger(__name__)

class CustomOAuth2Validator(OAuth2Validator):
    def filter_scopes_by_user_groups(self, user, requested_scopes):
            """
            Restrict scopes based on user group membership.
            Example: Only users in 'API_READERS' group get 'api.read',
            only users in 'API_WRITERS' get 'api.write', etc.
            """
            allowed_scopes = set()
            group_scope_map = {
                'API_READERS': {'api.read'},
                'API_WRITERS': { 'api.write'},
                'API_ADMINS': {'read', 'write', 'api.read', 'api.write'},
                # Add more group-to-scope mappings as needed
            }
            user_groups = set(g.name for g in user.groups.all())
            for group, scopes in group_scope_map.items():
                if group in user_groups:
                    allowed_scopes.update(scopes)
            # Always allow basic OIDC scopes
            allowed_scopes.update({'openid', 'profile', 'email', 'offline_access'})
            # Only return requested scopes that are allowed
            return [scope for scope in requested_scopes if scope in allowed_scopes]

    def finalize_id_token(self, id_token, token, token_handler, request):
        """
        Ensure 'aud' is set and force 'groups' and 'identity_provider' into ID token claims.
        """
        from django.conf import settings
        oidc_audience = getattr(settings, 'OAUTH2_PROVIDER', {}).get('OIDC_AUDIENCE', None)
        client_id = request.client.client_id if hasattr(request, 'client') else None
        audience = []
        if oidc_audience:
            audience = oidc_audience if isinstance(oidc_audience, list) else [oidc_audience]
        if client_id and client_id not in audience:
            audience.append(client_id)
        if audience:
            id_token['aud'] = audience

        # Force custom claims into ID token
        user = getattr(request, 'user', None)
        if user and user.is_authenticated:
            id_token['groups'] = list(user.groups.values_list('name', flat=True))
            # Use profile if available
            profile = None
            try:
                profile = self._get_user_profile(user)
            except Exception:
                profile = None
            id_token['identity_provider'] = profile.identity_provider if profile else 'local'

        return super().finalize_id_token(id_token, token, token_handler, request)
    
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
        """
        Add custom claims to ID token and access_token, including user's groups.
        """
        print("I am called from additional caims..")
        user = request.user
        profile = self._get_user_profile(user)
        from django.conf import settings
        # Base claims
        claims = {
            'sub': str(user.id),
            'auth_time': int(timezone.now().timestamp()),
        }
        # Set audience from settings (generic for all APIs)
        oidc_audience = getattr(settings, 'OAUTH2_PROVIDER', {}).get('OIDC_AUDIENCE', None)
        if oidc_audience:
            claims['aud'] = oidc_audience if isinstance(oidc_audience, list) else [oidc_audience]
        else:
            claims['aud'] = [request.client.client_id] if hasattr(request, 'client') else []
        # Add claims based on scopes
        scopes = set(request.scopes)
        if 'profile' in scopes:
            claims.update({
                'name': f'{user.first_name} {user.last_name}'.strip() or user.username,
                'given_name': user.first_name,
                'family_name': user.last_name,
                'preferred_username': user.username,
                'updated_at': int((user.last_login if user.last_login else user.date_joined).timestamp()),
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
        # --- Add user's groups to claims (for access_token) ---
        print("Adding groups to claims...", list(user.groups.values_list('name', flat=True)))
        claims['groups'] = list(user.groups.values_list('name', flat=True))
        print("Final claims being returned:", claims)
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
        Validate requested scopes against allowed scopes and user group membership.
        Dynamically add API scopes based on user group membership.
        """
        # Ensure openid scope is present for OIDC requests
        if 'openid' in scopes:
            if 'profile' not in scopes:
                scopes.append('profile')
            if 'email' not in scopes:
                scopes.append('email')

        # Dynamically add API scopes based on user group membership
        user = getattr(request, 'user', None)
        if user and user.is_authenticated:
            # Get all allowed scopes for this user
            allowed_scopes = set(self.filter_scopes_by_user_groups(user, [
                'read', 'write', 'api.read', 'api.write', 'openid', 'profile', 'email', 'offline_access'
            ]))
            # Add any allowed API scopes not already in the requested scopes
            for scope in allowed_scopes:
                if scope not in scopes:
                    scopes.append(scope)

        return super().validate_scopes(client_id, scopes, client, request, *args, **kwargs)