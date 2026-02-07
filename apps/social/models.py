# apps/social/models.py
"""
Models for social authentication tracking and auditing.
Note: These models extend social_django functionality, not replace it.
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinLengthValidator, URLValidator
from django.core.exceptions import ValidationError
import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Provider choices for consistent naming
SOCIAL_PROVIDER_CHOICES = [
    ('google-oauth2', _('Google')),
    ('facebook', _('Facebook')),
    ('github', _('GitHub')),
    ('microsoft-graph', _('Microsoft')),
    ('linkedin', _('LinkedIn')),
    ('azuread-oauth2', _('Azure AD')),
    ('okta-oauth2', _('Okta')),
    ('openid-connect', _('Generic OIDC')),
    ('twitter', _('Twitter')),
    ('apple-id', _('Apple ID')),
    ('slack', _('Slack')),
    ('discord', _('Discord')),
]


class SocialConnection(models.Model):
    """
    Extended social connection model that works alongside social_django's UserSocialAuth.
    This provides additional metadata and token management.
    """
    
    # Link to UserSocialAuth if available
    social_auth = models.OneToOneField(
        'social_django.UserSocialAuth',
        on_delete=models.CASCADE,
        related_name='extended_info',
        null=True,
        blank=True,
        verbose_name=_('Social Auth'),
        help_text=_('Link to social_django UserSocialAuth model')
    )
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='social_connections',
        verbose_name=_('User'),
        db_index=True
    )
    
    provider = models.CharField(
        max_length=50,
        choices=SOCIAL_PROVIDER_CHOICES,
        verbose_name=_('Provider'),
        db_index=True
    )
    
    provider_id = models.CharField(
        max_length=255,
        verbose_name=_('Provider User ID'),
        help_text=_('Unique identifier from the social provider'),
        db_index=True
    )
    
    email = models.EmailField(
        verbose_name=_('Email'),
        help_text=_('Email address from the social provider'),
        db_index=True
    )
    
    name = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_('Full Name'),
        help_text=_('Full name from the social provider')
    )
    
    picture_url = models.URLField(
        max_length=500,
        blank=True,
        validators=[URLValidator()],
        verbose_name=_('Profile Picture URL'),
        help_text=_('URL to the user\'s profile picture')
    )
    
    # Token management (encrypted in production)
    access_token = models.TextField(
        blank=True,
        verbose_name=_('Access Token'),
        help_text=_('OAuth2 access token (should be encrypted in production)')
    )
    
    refresh_token = models.TextField(
        blank=True,
        verbose_name=_('Refresh Token'),
        help_text=_('OAuth2 refresh token (should be encrypted in production)')
    )
    
    token_expiry = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Token Expiry'),
        help_text=_('When the access token expires')
    )
    
    # Additional metadata as JSON
    extra_data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_('Extra Data'),
        help_text=_('Additional provider-specific data in JSON format')
    )
    
    # Connection metadata
    scopes = models.TextField(
        blank=True,
        verbose_name=_('OAuth Scopes'),
        help_text=_('Granted OAuth scopes (space-separated)')
    )
    
    is_primary = models.BooleanField(
        default=False,
        verbose_name=_('Is Primary'),
        help_text=_('Is this the primary social connection for the user?')
    )
    
    is_active = models.BooleanField(
        default=True,
        verbose_name=_('Is Active'),
        help_text=_('Is this connection currently active?'),
        db_index=True
    )
    
    # Timestamps
    connected_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('Connected At')
    )
    
    last_used = models.DateTimeField(
        auto_now=True,
        verbose_name=_('Last Used'),
        db_index=True
    )
    
    last_synced = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Last Synced'),
        help_text=_('When profile data was last synced from the provider')
    )
    
    class Meta:
        verbose_name = _('Social Connection')
        verbose_name_plural = _('Social Connections')
        unique_together = ['provider', 'provider_id']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['provider', 'email']),
            models.Index(fields=['connected_at']),
        ]
        ordering = ['-last_used']
    
    def __str__(self):
        return f"{self.user.email} - {self.get_provider_display()}"
    
    def clean(self):
        """Validate model data"""
        super().clean()
        
        # Ensure provider_id is not empty for active connections
        if self.is_active and not self.provider_id:
            raise ValidationError({
                'provider_id': _('Provider ID is required for active connections')
            })
        
        # Validate email format
        if self.email and '@' not in self.email:
            raise ValidationError({
                'email': _('Enter a valid email address')
            })
    
    def update_token(self, access_token: str, refresh_token: Optional[str] = None, 
                    expires_in: Optional[int] = None, scopes: Optional[str] = None):
        """
        Update OAuth tokens and metadata
        
        Args:
            access_token: OAuth2 access token
            refresh_token: OAuth2 refresh token (optional)
            expires_in: Token expiry in seconds (optional)
            scopes: Granted OAuth scopes (optional)
        """
        self.access_token = access_token
        
        if refresh_token:
            self.refresh_token = refresh_token
        
        if expires_in:
            self.token_expiry = timezone.now() + timezone.timedelta(seconds=expires_in)
        
        if scopes:
            self.scopes = scopes
        
        self.last_used = timezone.now()
        self.save()
        
        logger.info(f"Updated token for {self.user.email} via {self.provider}")
    
    def is_token_expired(self) -> bool:
        """Check if access token is expired"""
        if not self.token_expiry:
            return True  # Assume expired if no expiry time
        
        return timezone.now() > self.token_expiry
    
    def get_extra_data_value(self, key: str, default: Any = None) -> Any:
        """
        Safely get a value from extra_data JSON
        
        Args:
            key: JSON key to retrieve
            default: Default value if key doesn't exist
            
        Returns:
            Value from extra_data or default
        """
        try:
            return self.extra_data.get(key, default)
        except (AttributeError, KeyError):
            return default
    
    def set_extra_data_value(self, key: str, value: Any):
        """
        Safely set a value in extra_data JSON
        
        Args:
            key: JSON key to set
            value: Value to set
        """
        if not isinstance(self.extra_data, dict):
            self.extra_data = {}
        
        self.extra_data[key] = value
        self.save(update_fields=['extra_data'])
    
    def sync_profile_data(self, profile_data: Dict[str, Any]):
        """
        Sync profile data from provider
        
        Args:
            profile_data: Dictionary of profile data from provider
        """
        update_fields = []
        
        # Update basic profile info
        if 'name' in profile_data and profile_data['name']:
            self.name = profile_data['name'][:255]
            update_fields.append('name')
        
        if 'picture' in profile_data and profile_data['picture']:
            self.picture_url = profile_data['picture'][:500]
            update_fields.append('picture_url')
        elif 'avatar_url' in profile_data and profile_data['avatar_url']:
            self.picture_url = profile_data['avatar_url'][:500]
            update_fields.append('picture_url')
        
        # Update extra data
        if 'extra' in profile_data and isinstance(profile_data['extra'], dict):
            self.extra_data.update(profile_data['extra'])
            update_fields.append('extra_data')
        
        self.last_synced = timezone.now()
        update_fields.append('last_synced')
        
        if update_fields:
            self.save(update_fields=update_fields)
        
        logger.info(f"Synced profile data for {self.user.email} via {self.provider}")
    
    @property
    def display_name(self) -> str:
        """Get display name (name or email)"""
        return self.name if self.name else self.email
    
    @property
    def token_info(self) -> Dict[str, Any]:
        """Get token information as dictionary"""
        return {
            'has_access_token': bool(self.access_token),
            'has_refresh_token': bool(self.refresh_token),
            'is_expired': self.is_token_expired(),
            'expires_at': self.token_expiry,
            'scopes': self.scopes.split() if self.scopes else [],
        }
    
    @classmethod
    def get_user_connections(cls, user: User, active_only: bool = True):
        """Get all social connections for a user"""
        queryset = cls.objects.filter(user=user)
        if active_only:
            queryset = queryset.filter(is_active=True)
        return queryset.order_by('-is_primary', '-last_used')
    
    @classmethod
    def get_connection_by_provider(cls, user: User, provider: str):
        """Get a specific social connection by provider"""
        try:
            return cls.objects.get(user=user, provider=provider, is_active=True)
        except cls.DoesNotExist:
            return None


class SocialLoginEvent(models.Model):
    """
    Audit log for social authentication events.
    This provides security monitoring and debugging capabilities.
    """
    
    EVENT_TYPES = [
        ('login', _('Login')),
        ('connect', _('Connect New Account')),
        ('disconnect', _('Disconnect Account')),
        ('token_refresh', _('Token Refresh')),
        ('error', _('Error')),
    ]
    
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='social_login_events',
        verbose_name=_('User'),
        db_index=True
    )
    
    event_type = models.CharField(
        max_length=20,
        choices=EVENT_TYPES,
        default='login',
        verbose_name=_('Event Type'),
        db_index=True
    )
    
    provider = models.CharField(
        max_length=50,
        choices=SOCIAL_PROVIDER_CHOICES,
        verbose_name=_('Provider'),
        db_index=True
    )
    
    provider_id = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_('Provider User ID'),
        help_text=_('User ID from the social provider')
    )
    
    email_attempted = models.EmailField(
        blank=True,
        verbose_name=_('Email Attempted'),
        help_text=_('Email address used in the authentication attempt')
    )
    
    # Status
    success = models.BooleanField(
        default=False,
        verbose_name=_('Success'),
        db_index=True
    )
    
    error_code = models.CharField(
        max_length=100,
        blank=True,
        verbose_name=_('Error Code'),
        help_text=_('Error code if authentication failed')
    )
    
    error_message = models.TextField(
        blank=True,
        verbose_name=_('Error Message'),
        help_text=_('Detailed error message if authentication failed')
    )
    
    # Request metadata
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_('IP Address'),
        db_index=True
    )
    
    user_agent = models.TextField(
        blank=True,
        verbose_name=_('User Agent'),
        help_text=_('HTTP User-Agent header from the request')
    )
    
    referer = models.URLField(
        blank=True,
        verbose_name=_('Referer'),
        help_text=_('HTTP Referer header')
    )
    
    # Additional context
    extra_data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_('Extra Data'),
        help_text=_('Additional context data in JSON format')
    )
    
    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('Created At'),
        db_index=True
    )
    
    duration_ms = models.IntegerField(
        null=True,
        blank=True,
        verbose_name=_('Duration (ms)'),
        help_text=_('How long the authentication took in milliseconds')
    )
    
    class Meta:
        verbose_name = _('Social Login Event')
        verbose_name_plural = _('Social Login Events')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['success', 'created_at']),
            models.Index(fields=['provider', 'created_at']),
            models.Index(fields=['email_attempted', 'created_at']),
        ]
    
    def __str__(self):
        status = _('Success') if self.success else _('Failed')
        return f"{self.get_event_type_display()} - {self.get_provider_display()} - {status}"
    
    def log_success(self, user: Optional[User] = None, **kwargs):
        """Log a successful authentication event"""
        self.success = True
        if user:
            self.user = user
        if kwargs:
            self.extra_data.update(kwargs)
        self.save()
        
        logger.info(f"Social auth success: {self.provider} for {self.email_attempted}")
    
    def log_error(self, error_code: str, error_message: str, **kwargs):
        """Log a failed authentication event"""
        self.success = False
        self.error_code = error_code
        self.error_message = error_message
        if kwargs:
            self.extra_data.update(kwargs)
        self.save()
        
        logger.warning(f"Social auth error: {self.provider} - {error_code}: {error_message}")
    
    @property
    def is_recent(self) -> bool:
        """Check if event occurred in the last 5 minutes"""
        return (timezone.now() - self.created_at).total_seconds() < 300
    
    @classmethod
    def create_login_event(cls, provider: str, email: str = '', ip_address: str = '', 
                          user_agent: str = '', **kwargs) -> 'SocialLoginEvent':
        """
        Create a new login event
        
        Args:
            provider: Social provider name
            email: Email address attempted
            ip_address: Client IP address
            user_agent: HTTP User-Agent
            **kwargs: Additional data for extra_data field
            
        Returns:
            SocialLoginEvent instance
        """
        return cls.objects.create(
            event_type='login',
            provider=provider,
            email_attempted=email,
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent else '',
            extra_data=kwargs or {}
        )
    
    @classmethod
    def get_recent_failures(cls, email: str, provider: str = '', 
                           minutes: int = 15) -> int:
        """
        Count recent failed attempts for an email
        
        Args:
            email: Email address to check
            provider: Optional provider filter
            minutes: Time window in minutes
            
        Returns:
            Number of recent failures
        """
        cutoff = timezone.now() - timezone.timedelta(minutes=minutes)
        queryset = cls.objects.filter(
            email_attempted=email,
            success=False,
            created_at__gte=cutoff
        )
        
        if provider:
            queryset = queryset.filter(provider=provider)
        
        return queryset.count()


# Signal handlers for integration with social_django
from django.db.models.signals import post_save
from django.dispatch import receiver
from social_django.models import UserSocialAuth

@receiver(post_save, sender=UserSocialAuth)
def create_social_connection_from_auth(sender, instance, created, **kwargs):
    """
    Create or update SocialConnection when UserSocialAuth is saved
    """
    try:
        # Get extra data from social auth
        extra_data = instance.extra_data or {}
        
        # Create or update SocialConnection
        connection, conn_created = SocialConnection.objects.update_or_create(
            social_auth=instance,
            defaults={
                'user': instance.user,
                'provider': instance.provider,
                'provider_id': instance.uid,
                'email': extra_data.get('email', instance.user.email),
                'name': extra_data.get('name', ''),
                'picture_url': extra_data.get('picture', '') or extra_data.get('avatar_url', ''),
                'extra_data': extra_data,
                'is_active': True,
            }
        )
        
        action = "created" if conn_created else "updated"
        logger.debug(f"SocialConnection {action} for user {instance.user.id} via {instance.provider}")
        
    except Exception as e:
        logger.error(f"Failed to create SocialConnection from UserSocialAuth: {e}")