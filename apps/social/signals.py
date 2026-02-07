# apps/social/signals.py
"""
Signal handlers for social authentication integration.
These signals synchronize data between social_django models and our custom models.
"""

import logging
import json
from typing import Dict, Any
from django.db import transaction
from django.db.models.signals import post_save, pre_delete, pre_save, post_delete
from django.dispatch import receiver
from django.utils import timezone
from django.contrib.auth.models import User
from social_django.models import UserSocialAuth
from .models import SocialConnection, SocialLoginEvent
from apps.core.models import UserProfile

logger = logging.getLogger(__name__)


@receiver(post_save, sender=User)
def handle_user_profile_sync(sender, instance: User, created: bool, **kwargs):
    """
    Sync user profile when User is saved
    This ensures UserProfile exists for social auth users
    """
    try:
        if created:
            # Create UserProfile for new users
            profile, profile_created = UserProfile.objects.get_or_create(user=instance)
            if profile_created:
                logger.debug(f"Created UserProfile for new user {instance.id}")
        elif not hasattr(instance, 'profile'):
            # Ensure UserProfile exists for existing users
            UserProfile.objects.get_or_create(user=instance)
            logger.debug(f"Ensured UserProfile exists for user {instance.id}")
    except Exception as e:
        logger.error(f"Failed to sync UserProfile for user {instance.id}: {e}")


@receiver(post_save, sender=UserSocialAuth)
def sync_social_connection_from_auth(sender, instance: UserSocialAuth, created: bool, **kwargs):
    """
    Create or update SocialConnection when UserSocialAuth is saved
    This maintains synchronization between social_django and our models
    """
    try:
        with transaction.atomic():
            # Extract data from UserSocialAuth
            extra_data = instance.extra_data or {}
            
            # Determine email from extra_data or user
            email = (
                extra_data.get('email') or 
                getattr(instance.user, 'email', '') or
                extra_data.get('mail') or
                extra_data.get('userPrincipalName', '')
            )
            
            # Determine name from extra_data
            name = (
                extra_data.get('name') or
                extra_data.get('displayName') or
                extra_data.get('fullname') or
                f"{extra_data.get('first_name', '')} {extra_data.get('last_name', '')}".strip() or
                instance.user.get_full_name()
            )
            
            # Determine picture URL
            picture_url = (
                extra_data.get('picture') or
                extra_data.get('avatar_url') or
                extra_data.get('pictureUrl') or
                extra_data.get('avatar') or
                ''
            )
            
            # Check if email is verified
            email_verified = extra_data.get('email_verified', False)
            if isinstance(email_verified, str):
                email_verified = email_verified.lower() in ['true', '1', 'yes']
            
            # Prepare defaults for SocialConnection
            defaults = {
                'user': instance.user,
                'provider': instance.provider,
                'provider_id': instance.uid,
                'email': email,
                'name': name[:255] if name else '',
                'picture_url': picture_url[:500] if picture_url else '',
                'extra_data': extra_data,
                'is_active': True,
                'last_used': timezone.now(),
            }
            
            # Try to get existing SocialConnection
            try:
                # First try to find by social_auth foreign key
                social_connection = SocialConnection.objects.get(social_auth=instance)
                action = "updated"
                
                # Update fields
                for field, value in defaults.items():
                    if field != 'user':  # Don't change user
                        setattr(social_connection, field, value)
                
                social_connection.save()
                
            except SocialConnection.DoesNotExist:
                # Try to find by provider and provider_id
                try:
                    social_connection = SocialConnection.objects.get(
                        provider=instance.provider,
                        provider_id=instance.uid
                    )
                    action = "updated"
                    
                    # Link to social_auth and update
                    social_connection.social_auth = instance
                    for field, value in defaults.items():
                        if field != 'user':
                            setattr(social_connection, field, value)
                    
                    social_connection.save()
                    
                except SocialConnection.DoesNotExist:
                    # Create new SocialConnection
                    social_connection = SocialConnection.objects.create(
                        social_auth=instance,
                        **defaults
                    )
                    action = "created"
            
            # Update UserProfile if needed
            try:
                profile = instance.user.profile
                
                # Update identity provider if this is the first/primary connection
                connections_count = SocialConnection.objects.filter(
                    user=instance.user, 
                    is_active=True
                ).count()
                
                if connections_count == 1 or not profile.identity_provider or profile.identity_provider == 'local':
                    profile.identity_provider = instance.provider.replace('-oauth2', '').replace('-graph', '')
                    profile.external_id = instance.uid
                    profile.email_verified = email_verified or profile.email_verified
                    profile.save(update_fields=['identity_provider', 'external_id', 'email_verified'])
                    
                    logger.debug(f"Updated UserProfile identity provider for user {instance.user.id}")
            
            except (UserProfile.DoesNotExist, AttributeError) as e:
                logger.warning(f"Could not update UserProfile for user {instance.user.id}: {e}")
            
            # Log the sync action
            logger.info(
                f"SocialConnection {action} for user {instance.user.id} "
                f"via {instance.provider} (UserSocialAuth ID: {instance.id})"
            )
            
            # Create audit log entry
            try:
                SocialLoginEvent.objects.create(
                    user=instance.user,
                    event_type='connect' if action == 'created' else 'reconnect',
                    provider=instance.provider,
                    provider_id=instance.uid,
                    email_attempted=email,
                    success=True,
                    extra_data={'action': action, 'social_auth_id': instance.id}
                )
            except Exception as e:
                logger.error(f"Failed to create SocialLoginEvent for sync: {e}")
                
    except Exception as e:
        logger.error(
            f"Failed to sync SocialConnection from UserSocialAuth "
            f"(user: {instance.user.id if instance.user else 'N/A'}, "
            f"provider: {instance.provider}): {e}",
            exc_info=True
        )


@receiver(pre_delete, sender=UserSocialAuth)
def handle_social_auth_deletion(sender, instance: UserSocialAuth, **kwargs):
    """
    Handle UserSocialAuth deletion by deactivating SocialConnection
    We deactivate rather than delete for audit purposes
    """
    try:
        # Find associated SocialConnection
        try:
            # First try by social_auth foreign key
            social_connection = SocialConnection.objects.get(social_auth=instance)
        except SocialConnection.DoesNotExist:
            # Try by provider and provider_id
            try:
                social_connection = SocialConnection.objects.get(
                    provider=instance.provider,
                    provider_id=instance.uid
                )
            except SocialConnection.DoesNotExist:
                logger.warning(
                    f"No SocialConnection found for UserSocialAuth deletion "
                    f"(user: {instance.user.id}, provider: {instance.provider})"
                )
                return
        
        # Deactivate the SocialConnection
        social_connection.is_active = False
        social_connection.save(update_fields=['is_active'])
        
        # Check if this was the primary connection
        if social_connection.is_primary:
            # Find another active connection to make primary
            other_active = SocialConnection.objects.filter(
                user=instance.user,
                is_active=True
            ).exclude(id=social_connection.id).first()
            
            if other_active:
                other_active.is_primary = True
                other_active.save(update_fields=['is_primary'])
                logger.info(
                    f"Set {other_active.provider} as primary for user {instance.user.id} "
                    f"after {social_connection.provider} deletion"
                )
        
        # Create audit log entry
        try:
            SocialLoginEvent.objects.create(
                user=instance.user,
                event_type='disconnect',
                provider=instance.provider,
                provider_id=instance.uid,
                email_attempted=social_connection.email,
                success=True,
                extra_data={
                    'social_auth_id': instance.id,
                    'was_primary': social_connection.is_primary
                }
            )
        except Exception as e:
            logger.error(f"Failed to create SocialLoginEvent for deletion: {e}")
        
        logger.info(
            f"Deactivated SocialConnection for user {instance.user.id} "
            f"via {instance.provider} (UserSocialAuth ID: {instance.id})"
        )
        
    except Exception as e:
        logger.error(
            f"Failed to handle UserSocialAuth deletion "
            f"(user: {instance.user.id if instance.user else 'N/A'}, "
            f"provider: {instance.provider}): {e}",
            exc_info=True
        )


@receiver(post_save, sender=SocialConnection)
def handle_social_connection_update(sender, instance: SocialConnection, created: bool, **kwargs):
    """
    Handle SocialConnection updates to ensure data consistency
    """
    try:
        # If this connection is marked as primary, ensure no other primary exists
        if instance.is_primary and instance.is_active:
            # Remove primary flag from other connections
            other_primaries = SocialConnection.objects.filter(
                user=instance.user,
                is_primary=True,
                is_active=True
            ).exclude(id=instance.id)
            
            if other_primaries.exists():
                other_primaries.update(is_primary=False)
                logger.debug(
                    f"Cleared primary flag from other connections for user {instance.user.id}"
                )
        
        # Update UserSocialAuth if linked
        if instance.social_auth and instance.is_active:
            try:
                # Update extra_data if it has changed
                if instance.extra_data:
                    instance.social_auth.extra_data = instance.extra_data
                    instance.social_auth.save(update_fields=['extra_data'])
            except Exception as e:
                logger.warning(f"Failed to update UserSocialAuth extra_data: {e}")
        
        # Log connection state changes
        if 'update_fields' in kwargs and kwargs['update_fields']:
            updated_fields = kwargs['update_fields']
            
            if 'is_active' in updated_fields:
                action = "activated" if instance.is_active else "deactivated"
                logger.info(
                    f"SocialConnection {action} for user {instance.user.id} "
                    f"via {instance.provider}"
                )
            
            if 'is_primary' in updated_fields and instance.is_primary:
                logger.info(
                    f"SocialConnection set as primary for user {instance.user.id} "
                    f"via {instance.provider}"
                )
        
    except Exception as e:
        logger.error(
            f"Failed to handle SocialConnection update "
            f"(user: {instance.user.id}, provider: {instance.provider}): {e}",
            exc_info=True
        )


@receiver(pre_delete, sender=SocialConnection)
def handle_social_connection_deletion(sender, instance: SocialConnection, **kwargs):
    """
    Handle SocialConnection deletion
    This should rarely happen as we usually deactivate rather than delete
    """
    try:
        # Check if this is the only active connection
        active_count = SocialConnection.objects.filter(
            user=instance.user,
            is_active=True
        ).exclude(id=instance.id).count()
        
        has_password = instance.user.has_usable_password()
        
        # Warn if deleting might lock user out
        if active_count == 0 and not has_password:
            logger.warning(
                f"Deleting SocialConnection for user {instance.user.id} via {instance.provider} "
                f"might lock user out (no other login methods)"
            )
        
        # Create audit log entry
        SocialLoginEvent.objects.create(
            user=instance.user,
            event_type='disconnect',
            provider=instance.provider,
            provider_id=instance.provider_id,
            email_attempted=instance.email,
            success=True,
            extra_data={
                'deleted': True,
                'was_primary': instance.is_primary,
                'had_password': has_password
            }
        )
        
        logger.info(
            f"Deleted SocialConnection for user {instance.user.id} via {instance.provider}"
        )
        
    except Exception as e:
        logger.error(
            f"Failed to handle SocialConnection deletion "
            f"(user: {instance.user.id}, provider: {instance.provider}): {e}",
            exc_info=True
        )


@receiver(pre_save, sender=SocialLoginEvent)
def enrich_social_login_event(sender, instance: SocialLoginEvent, **kwargs):
    """
    Enrich SocialLoginEvent with additional context before saving
    """
    try:
        # Ensure event has a timestamp
        if not instance.created_at:
            instance.created_at = timezone.now()
        
        # Parse user agent for additional context
        if instance.user_agent:
            # Simple user agent parsing (in production, use a library like user_agents)
            ua = instance.user_agent.lower()
            
            extra_data = instance.extra_data or {}
            
            # Detect browser
            if 'chrome' in ua and 'chromium' not in ua:
                extra_data['browser'] = 'Chrome'
            elif 'firefox' in ua:
                extra_data['browser'] = 'Firefox'
            elif 'safari' in ua and 'chrome' not in ua:
                extra_data['browser'] = 'Safari'
            elif 'edge' in ua:
                extra_data['browser'] = 'Edge'
            elif 'opera' in ua:
                extra_data['browser'] = 'Opera'
            
            # Detect OS
            if 'windows' in ua:
                extra_data['os'] = 'Windows'
            elif 'mac os' in ua or 'macintosh' in ua:
                extra_data['os'] = 'macOS'
            elif 'linux' in ua:
                extra_data['os'] = 'Linux'
            elif 'android' in ua:
                extra_data['os'] = 'Android'
            elif 'iphone' in ua or 'ipad' in ua:
                extra_data['os'] = 'iOS'
            
            instance.extra_data = extra_data
        
        # Add geolocation hint from IP (in production, use a geolocation service)
        if instance.ip_address and not instance.ip_address.startswith('127.'):
            # This is a placeholder - in production, use a service like geoip2
            extra_data = instance.extra_data or {}
            
            # Simple IP type detection
            if instance.ip_address.count('.') == 3:
                extra_data['ip_type'] = 'IPv4'
            elif ':' in instance.ip_address:
                extra_data['ip_type'] = 'IPv6'
            
            instance.extra_data = extra_data
        
    except Exception as e:
        logger.warning(f"Failed to enrich SocialLoginEvent: {e}")


@receiver(post_save, sender=SocialLoginEvent)
def handle_failed_login_alert(sender, instance: SocialLoginEvent, created: bool, **kwargs):
    """
    Alert on suspicious login patterns
    """
    try:
        if not created:
            return
        
        # Check for rapid failed attempts
        if not instance.success and instance.email_attempted:
            cutoff = timezone.now() - timezone.timedelta(minutes=5)
            
            recent_failures = SocialLoginEvent.objects.filter(
                email_attempted=instance.email_attempted,
                provider=instance.provider,
                success=False,
                created_at__gte=cutoff
            ).count()
            
            if recent_failures >= 3:
                logger.warning(
                    f"Suspicious login activity detected: "
                    f"{recent_failures} failed attempts for {instance.email_attempted} "
                    f"via {instance.provider} in the last 5 minutes"
                )
                
                # In production, you might:
                # 1. Send an email alert
                # 2. Trigger a webhook
                # 3. Temporarily block the IP
                # 4. Increase logging level
        
        # Check for login from new location/device
        if instance.success and instance.user and instance.ip_address:
            # Get previous successful logins
            previous_logins = SocialLoginEvent.objects.filter(
                user=instance.user,
                provider=instance.provider,
                success=True
            ).exclude(id=instance.id).order_by('-created_at')
            
            if previous_logins.exists():
                last_login = previous_logins.first()
                
                # Check if IP changed significantly
                if last_login.ip_address != instance.ip_address:
                    # Simple check: different network class
                    def get_network_class(ip):
                        if '.' in ip:
                            return '.'.join(ip.split('.')[:2])  # First two octets
                        return None
                    
                    old_network = get_network_class(last_login.ip_address)
                    new_network = get_network_class(instance.ip_address)
                    
                    if old_network and new_network and old_network != new_network:
                        logger.info(
                            f"User {instance.user.id} logged in from new network: "
                            f"{instance.ip_address} (previous: {last_login.ip_address})"
                        )
                        
                        # Update extra_data with location change info
                        instance.extra_data = instance.extra_data or {}
                        instance.extra_data['location_change'] = True
                        instance.extra_data['previous_ip'] = last_login.ip_address
                        instance.save(update_fields=['extra_data'])
                
    except Exception as e:
        logger.error(f"Failed to handle login alert: {e}")


def register_signals():
    """
    Explicitly register signals
    This can be called from apps.py to ensure signals are connected
    """
    # Signals are already connected via @receiver decorators
    # This function provides an explicit way to ensure registration
    logger.debug("Social authentication signals registered")