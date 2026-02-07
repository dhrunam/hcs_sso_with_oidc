# apps/social/serializers.py
"""
Serializers for social authentication API endpoints.
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from .models import SocialConnection, SocialLoginEvent
from apps.core.models import UserProfile
import logging

logger = logging.getLogger(__name__)


# Provider configuration constants
PROVIDER_CONFIG = {
    'google-oauth2': {
        'display_name': 'Google',
        'icon': 'fab fa-google',
        'color': '#4285F4',
        'scopes': ['openid', 'email', 'profile'],
    },
    'facebook': {
        'display_name': 'Facebook',
        'icon': 'fab fa-facebook',
        'color': '#1877F2',
        'scopes': ['email', 'public_profile'],
    },
    'microsoft-graph': {
        'display_name': 'Microsoft',
        'icon': 'fab fa-microsoft',
        'color': '#00A4EF',
        'scopes': ['User.Read'],
    },
    'github': {
        'display_name': 'GitHub',
        'icon': 'fab fa-github',
        'color': '#181717',
        'scopes': ['user:email'],
    },
    'linkedin': {
        'display_name': 'LinkedIn',
        'icon': 'fab fa-linkedin',
        'color': '#0A66C2',
        'scopes': ['r_liteprofile', 'r_emailaddress'],
    },
    'azuread-oauth2': {
        'display_name': 'Azure AD',
        'icon': 'fas fa-cloud',
        'color': '#0078D4',
        'scopes': ['openid', 'email', 'profile'],
    },
    'okta-oauth2': {
        'display_name': 'Okta',
        'icon': 'fas fa-lock',
        'color': '#007DC1',
        'scopes': ['openid', 'email', 'profile'],
    },
    'openid-connect': {
        'display_name': 'OpenID Connect',
        'icon': 'fas fa-id-card',
        'color': '#F47C20',
        'scopes': ['openid', 'email', 'profile'],
    },
    'apple-id': {
        'display_name': 'Apple',
        'icon': 'fab fa-apple',
        'color': '#000000',
        'scopes': ['email', 'name'],
    },
    'slack': {
        'display_name': 'Slack',
        'icon': 'fab fa-slack',
        'color': '#4A154B',
        'scopes': ['identity.basic', 'identity.email'],
    },
    'discord': {
        'display_name': 'Discord',
        'icon': 'fab fa-discord',
        'color': '#5865F2',
        'scopes': ['identify', 'email'],
    },
}

ALLOWED_PROVIDERS = list(PROVIDER_CONFIG.keys())


class SocialProviderSerializer(serializers.Serializer):
    """Serializer for social provider information"""
    
    id = serializers.CharField(source='key')
    name = serializers.SerializerMethodField()
    display_name = serializers.SerializerMethodField()
    icon = serializers.SerializerMethodField()
    color = serializers.SerializerMethodField()
    login_url = serializers.SerializerMethodField()
    scopes = serializers.SerializerMethodField()
    is_enabled = serializers.SerializerMethodField()
    
    def get_name(self, obj):
        """Get provider internal name"""
        return obj[0]  # Provider key
    
    def get_display_name(self, obj):
        """Get user-friendly display name"""
        provider_key = obj[0]
        return PROVIDER_CONFIG.get(provider_key, {}).get('display_name', provider_key.title())
    
    def get_icon(self, obj):
        """Get provider icon class"""
        provider_key = obj[0]
        return PROVIDER_CONFIG.get(provider_key, {}).get('icon', 'fas fa-user')
    
    def get_color(self, obj):
        """Get provider brand color"""
        provider_key = obj[0]
        return PROVIDER_CONFIG.get(provider_key, {}).get('color', '#6c757d')
    
    def get_login_url(self, obj):
        """Get OAuth login URL"""
        provider_key = obj[0]
        request = self.context.get('request')
        if request:
            return request.build_absolute_uri(f'/api/social/login/{provider_key}/')
        return f'/api/social/login/{provider_key}/'
    
    def get_scopes(self, obj):
        """Get required OAuth scopes"""
        provider_key = obj[0]
        return PROVIDER_CONFIG.get(provider_key, {}).get('scopes', [])
    
    def get_is_enabled(self, obj):
        """Check if provider is enabled in settings"""
        provider_key = obj[0]
        # Check if provider is configured in settings
        # Example: SOCIAL_AUTH_GOOGLE_OAUTH2_KEY for Google
        from django.conf import settings
        
        setting_map = {
            'google-oauth2': 'SOCIAL_AUTH_GOOGLE_OAUTH2_KEY',
            'facebook': 'SOCIAL_AUTH_FACEBOOK_KEY',
            'microsoft-graph': 'SOCIAL_AUTH_MICROSOFT_KEY',
            'github': 'SOCIAL_AUTH_GITHUB_KEY',
            'linkedin': 'SOCIAL_AUTH_LINKEDIN_KEY',
            'azuread-oauth2': 'SOCIAL_AUTH_AZUREAD_OAUTH2_KEY',
            'okta-oauth2': 'SOCIAL_AUTH_OKTA_OAUTH2_KEY',
            'openid-connect': 'SOCIAL_AUTH_OIDC_KEY',
        }
        
        setting_name = setting_map.get(provider_key)
        if setting_name:
            return bool(getattr(settings, setting_name, None))
        
        return False


class SocialConnectionSerializer(serializers.ModelSerializer):
    """Serializer for social connections"""
    
    provider_display = serializers.SerializerMethodField()
    provider_icon = serializers.SerializerMethodField()
    provider_color = serializers.SerializerMethodField()
    can_disconnect = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()
    token_info = serializers.SerializerMethodField()
    last_synced_formatted = serializers.SerializerMethodField()
    
    class Meta:
        model = SocialConnection
        fields = [
            'id', 'provider', 'provider_display', 'provider_icon', 'provider_color',
            'provider_id', 'email', 'name', 'picture_url',
            'connected_at', 'last_used', 'last_synced', 'last_synced_formatted',
            'is_active', 'is_primary', 'can_disconnect', 'is_expired', 'token_info'
        ]
        read_only_fields = fields
    
    def get_provider_display(self, obj):
        """Get display name for provider"""
        return PROVIDER_CONFIG.get(obj.provider, {}).get('display_name', obj.provider.title())
    
    def get_provider_icon(self, obj):
        """Get icon class for provider"""
        return PROVIDER_CONFIG.get(obj.provider, {}).get('icon', 'fas fa-user')
    
    def get_provider_color(self, obj):
        """Get provider brand color"""
        return PROVIDER_CONFIG.get(obj.provider, {}).get('color', '#6c757d')
    
    def get_can_disconnect(self, obj):
        """Check if user can disconnect this social account"""
        request = self.context.get('request')
        if not request or not request.user:
            return False
        
        user = request.user
        
        # Count active social connections (excluding this one)
        active_connections = SocialConnection.objects.filter(
            user=user, is_active=True
        ).exclude(id=obj.id).count()
        
        # Check if user has a usable password
        has_password = user.has_usable_password()
        
        # Can disconnect if user has password or other active connections
        can_disconnect = has_password or active_connections > 0
        
        # Additional safety: Don't allow disconnecting if this is primary
        if obj.is_primary and active_connections == 0 and not has_password:
            can_disconnect = False
        
        return can_disconnect
    
    def get_is_expired(self, obj):
        """Check if token is expired"""
        return obj.is_token_expired()
    
    def get_token_info(self, obj):
        """Get token information"""
        return {
            'has_access_token': bool(obj.access_token),
            'has_refresh_token': bool(obj.refresh_token),
            'is_expired': obj.is_token_expired(),
            'expires_at': obj.token_expiry,
            'scopes': obj.scopes.split() if obj.scopes else [],
        }
    
    def get_last_synced_formatted(self, obj):
        """Get formatted last synced time"""
        if not obj.last_synced:
            return None
        
        # Format for human readability
        from django.utils.timesince import timesince
        return f"{timesince(obj.last_synced)} ago"


class SocialLoginEventSerializer(serializers.ModelSerializer):
    """Serializer for social login events"""
    
    provider_display = serializers.SerializerMethodField()
    provider_icon = serializers.SerializerMethodField()
    event_type_display = serializers.SerializerMethodField()
    is_recent = serializers.SerializerMethodField()
    duration_formatted = serializers.SerializerMethodField()
    
    class Meta:
        model = SocialLoginEvent
        fields = [
            'id', 'event_type', 'event_type_display',
            'provider', 'provider_display', 'provider_icon',
            'provider_id', 'email_attempted', 
            'success', 'error_code', 'error_message',
            'ip_address', 'user_agent', 'referer',
            'created_at', 'duration_ms', 'duration_formatted', 'is_recent',
            'extra_data'
        ]
        read_only_fields = fields
    
    def get_provider_display(self, obj):
        """Get display name for provider"""
        return PROVIDER_CONFIG.get(obj.provider, {}).get('display_name', obj.provider.title())
    
    def get_provider_icon(self, obj):
        """Get icon class for provider"""
        return PROVIDER_CONFIG.get(obj.provider, {}).get('icon', 'fas fa-user')
    
    def get_event_type_display(self, obj):
        """Get display name for event type"""
        event_types = dict(SocialLoginEvent.EVENT_TYPES)
        return event_types.get(obj.event_type, obj.event_type.title())
    
    def get_is_recent(self, obj):
        """Check if event is recent (within last 5 minutes)"""
        return obj.is_recent
    
    def get_duration_formatted(self, obj):
        """Format duration for display"""
        if not obj.duration_ms:
            return None
        
        if obj.duration_ms < 1000:
            return f"{obj.duration_ms}ms"
        elif obj.duration_ms < 60000:
            return f"{obj.duration_ms / 1000:.1f}s"
        else:
            minutes = obj.duration_ms // 60000
            seconds = (obj.duration_ms % 60000) / 1000
            return f"{minutes}m {seconds:.1f}s"


class ConnectSocialSerializer(serializers.Serializer):
    """Serializer for connecting social accounts via direct token"""
    
    provider = serializers.ChoiceField(
        choices=[(p, p) for p in ALLOWED_PROVIDERS],
        help_text=_("Social provider identifier")
    )
    access_token = serializers.CharField(
        max_length=5000,
        help_text=_("OAuth2 access token"),
        trim_whitespace=False
    )
    id_token = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=5000,
        help_text=_("OpenID Connect ID token (for OIDC providers)"),
        trim_whitespace=False
    )
    refresh_token = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=5000,
        help_text=_("OAuth2 refresh token"),
        trim_whitespace=False
    )
    expires_in = serializers.IntegerField(
        required=False,
        min_value=1,
        max_value=86400,
        help_text=_("Token expiry in seconds")
    )
    scopes = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text=_("Space-separated list of granted scopes")
    )
    extra_data = serializers.JSONField(
        required=False,
        default=dict,
        help_text=_("Additional provider-specific data")
    )
    
    def validate_access_token(self, value):
        """Validate access token format"""
        if not value or len(value) < 10:
            raise serializers.ValidationError(_("Invalid access token"))
        
        # Basic token format validation
        # JWT tokens are base64 encoded and have 3 parts separated by dots
        if '.' in value and len(value.split('.')) == 3:
            # Likely a JWT token
            try:
                import base64
                import json
                
                # Decode the payload (middle part)
                parts = value.split('.')
                payload = parts[1]
                
                # Add padding if needed
                payload += '=' * (4 - len(payload) % 4)
                decoded = base64.b64decode(payload)
                json.loads(decoded)
                
            except (ValueError, TypeError, json.JSONDecodeError):
                # Not a valid JWT, but could be another token format
                pass
        
        return value
    
    def validate_id_token(self, value):
        """Validate ID token format"""
        if not value:
            return value
        
        # Similar validation as access token
        if len(value) < 10:
            raise serializers.ValidationError(_("Invalid ID token"))
        
        return value
    
    def validate(self, data):
        """Validate the entire connection request"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError(_("Authentication required"))
        
        provider = data.get('provider')
        user = request.user
        
        # Check if connection already exists
        existing = SocialConnection.objects.filter(
            user=user, 
            provider=provider,
            is_active=True
        ).first()
        
        if existing:
            raise serializers.ValidationError({
                'provider': _(f"You already have a {provider} account connected")
            })
        
        # Validate provider-specific requirements
        if provider in ['google-oauth2', 'azuread-oauth2', 'okta-oauth2', 'openid-connect']:
            # OIDC providers should have an id_token
            if not data.get('id_token'):
                logger.warning(f"OIDC provider {provider} connected without ID token")
        
        return data


class DisconnectSocialSerializer(serializers.Serializer):
    """Serializer for disconnecting social accounts"""
    
    provider = serializers.ChoiceField(
        choices=[(p, p) for p in ALLOWED_PROVIDERS],
        help_text=_("Social provider identifier")
    )
    confirm = serializers.BooleanField(
        default=False,
        help_text=_("Confirm that you want to disconnect this account")
    )
    
    def validate(self, data):
        """Validate that user won't be locked out"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError(_("Authentication required"))
        
        provider = data['provider']
        confirm = data.get('confirm', False)
        user = request.user
        
        if not confirm:
            raise serializers.ValidationError({
                'confirm': _("Please confirm you want to disconnect this account")
            })
        
        # Get the connection to disconnect
        try:
            connection = SocialConnection.objects.get(
                user=user, 
                provider=provider,
                is_active=True
            )
        except SocialConnection.DoesNotExist:
            raise serializers.ValidationError({
                'provider': _(f"You don't have an active {provider} connection")
            })
        
        # Check if this is the user's only login method
        active_connections = SocialConnection.objects.filter(
            user=user, is_active=True
        ).exclude(id=connection.id).count()
        
        has_password = user.has_usable_password()
        
        if active_connections == 0 and not has_password:
            raise serializers.ValidationError({
                'provider': _(
                    "Cannot disconnect your only login method. "
                    "Please set a password first or connect another account."
                )
            })
        
        # Check if this is the primary connection
        if connection.is_primary:
            # If disconnecting primary, we need to designate a new primary
            other_connections = SocialConnection.objects.filter(
                user=user, is_active=True
            ).exclude(id=connection.id)
            
            if other_connections.exists():
                # Automatically make another connection primary
                data['new_primary'] = other_connections.first()
            elif has_password:
                # User will use password login
                data['use_password_login'] = True
            else:
                # This should have been caught above, but just in case
                raise serializers.ValidationError({
                    'provider': _("Cannot disconnect primary login without alternative")
                })
        
        data['connection'] = connection
        return data


class RefreshSocialTokenSerializer(serializers.Serializer):
    """Serializer for refreshing social tokens"""
    
    provider = serializers.ChoiceField(
        choices=[(p, p) for p in ALLOWED_PROVIDERS],
        help_text=_("Social provider identifier")
    )
    
    def validate(self, data):
        """Validate token refresh request"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError(_("Authentication required"))
        
        provider = data['provider']
        user = request.user
        
        # Check if connection exists
        try:
            connection = SocialConnection.objects.get(
                user=user, 
                provider=provider,
                is_active=True
            )
        except SocialConnection.DoesNotExist:
            raise serializers.ValidationError({
                'provider': _(f"You don't have an active {provider} connection")
            })
        
        # Check if token has refresh capability
        if not connection.refresh_token:
            raise serializers.ValidationError({
                'provider': _(f"{provider} connection doesn't support token refresh")
            })
        
        data['connection'] = connection
        return data


class SyncSocialProfileSerializer(serializers.Serializer):
    """Serializer for syncing social profile data"""
    
    provider = serializers.ChoiceField(
        choices=[(p, p) for p in ALLOWED_PROVIDERS],
        help_text=_("Social provider identifier")
    )
    
    def validate(self, data):
        """Validate profile sync request"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError(_("Authentication required"))
        
        provider = data['provider']
        user = request.user
        
        # Check if connection exists
        try:
            connection = SocialConnection.objects.get(
                user=user, 
                provider=provider,
                is_active=True
            )
        except SocialConnection.DoesNotExist:
            raise serializers.ValidationError({
                'provider': _(f"You don't have an active {provider} connection")
            })
        
        data['connection'] = connection
        return data


class SetPrimaryConnectionSerializer(serializers.Serializer):
    """Serializer for setting primary social connection"""
    
    provider = serializers.ChoiceField(
        choices=[(p, p) for p in ALLOWED_PROVIDERS],
        help_text=_("Social provider identifier")
    )
    
    def validate(self, data):
        """Validate primary connection request"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError(_("Authentication required"))
        
        provider = data['provider']
        user = request.user
        
        # Check if connection exists and is active
        try:
            connection = SocialConnection.objects.get(
                user=user, 
                provider=provider,
                is_active=True
            )
        except SocialConnection.DoesNotExist:
            raise serializers.ValidationError({
                'provider': _(f"You don't have an active {provider} connection")
            })
        
        # Check if already primary
        if connection.is_primary:
            raise serializers.ValidationError({
                'provider': _(f"{provider} is already your primary connection")
            })
        
        data['connection'] = connection
        return data


# Utility function to get available providers
def get_available_providers(request=None):
    """
    Get list of available social providers
    
    Args:
        request: HTTP request for context
    
    Returns:
        List of provider tuples (id, display_name)
    """
    from django.conf import settings
    
    providers = []
    
    for provider_key, config in PROVIDER_CONFIG.items():
        # Check if provider is enabled in settings
        setting_map = {
            'google-oauth2': 'SOCIAL_AUTH_GOOGLE_OAUTH2_KEY',
            'facebook': 'SOCIAL_AUTH_FACEBOOK_KEY',
            'microsoft-graph': 'SOCIAL_AUTH_MICROSOFT_KEY',
            'github': 'SOCIAL_AUTH_GITHUB_KEY',
            'linkedin': 'SOCIAL_AUTH_LINKEDIN_KEY',
            'azuread-oauth2': 'SOCIAL_AUTH_AZUREAD_OAUTH2_KEY',
            'okta-oauth2': 'SOCIAL_AUTH_OKTA_OAUTH2_KEY',
            'openid-connect': 'SOCIAL_AUTH_OIDC_KEY',
        }
        
        setting_name = setting_map.get(provider_key)
        is_enabled = True
        
        if setting_name:
            is_enabled = bool(getattr(settings, setting_name, None))
        
        if is_enabled:
            providers.append((provider_key, config['display_name']))
    
    return providers