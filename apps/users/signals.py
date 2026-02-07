# apps/users/signals.py
"""
Signal handlers for user and profile lifecycle management.
These signals handle automatic profile creation, audit logging,
and synchronization between User and UserProfile models.
"""

import logging
from typing import Optional
from django.db import transaction
from django.db.models.signals import (
    post_save, pre_save, post_delete, 
    m2m_changed, pre_delete
)
from django.dispatch import receiver
from django.contrib.auth.models import User, Group, Permission
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string

from apps.core.models import UserProfile, Department, Organization
from apps.social.models import SocialConnection, SocialLoginEvent
from apps.users.tasks import send_welcome_email, send_password_reset_email

logger = logging.getLogger(__name__)


@receiver(post_save, sender=User)
def handle_user_creation(sender, instance: User, created: bool, **kwargs):
    """
    Handle user creation - create profile and perform initial setup
    
    This runs after a User is saved, handling both creation and updates.
    """
    try:
        with transaction.atomic():
            if created:
                # Create UserProfile for new user
                profile, profile_created = UserProfile.objects.get_or_create(
                    user=instance,
                    defaults={
                        'identity_provider': 'local',
                        'email_verified': False,
                        'preferred_language': getattr(
                            settings, 'DEFAULT_LANGUAGE', 'en'
                        ),
                        'timezone': getattr(settings, 'TIME_ZONE', 'UTC'),
                    }
                )
                
                # Assign default groups
                default_groups = getattr(settings, 'DEFAULT_USER_GROUPS', [])
                if default_groups:
                    groups = Group.objects.filter(name__in=default_groups)
                    if groups.exists():
                        instance.groups.add(*groups)
                        logger.debug(
                            f"Assigned default groups to new user {instance.id}: "
                            f"{', '.join([g.name for g in groups])}"
                        )
                
                # Send welcome email if configured
                if getattr(settings, 'SEND_WELCOME_EMAIL', False) and instance.email:
                    try:
                        # Use Celery task if available, otherwise send synchronously
                        if hasattr(settings, 'CELERY_BROKER_URL'):
                            send_welcome_email.delay(instance.id)
                        else:
                            send_welcome_email_sync(instance)
                    except Exception as e:
                        logger.error(f"Failed to send welcome email to {instance.email}: {e}")
                
                # Log user creation
                logger.info(
                    f"User created: {instance.username} ({instance.email}) "
                    f"with profile ID: {profile.id}"
                )
                
                # Create audit event
                SocialLoginEvent.objects.create(
                    user=instance,
                    event_type='connect',  # Reusing for account creation
                    provider='local',
                    email_attempted=instance.email,
                    success=True,
                    extra_data={
                        'action': 'user_created',
                        'signup_method': 'local',
                        'profile_created': profile_created
                    }
                )
            
            else:
                # Handle user updates
                update_fields = kwargs.get('update_fields', set())
                
                # Check if email was updated (requires verification)
                if 'email' in update_fields and instance.email:
                    old_user = User.objects.get(pk=instance.pk)
                    if old_user.email != instance.email:
                        # Email changed - mark as unverified
                        try:
                            profile = instance.profile
                            profile.email_verified = False
                            profile.save(update_fields=['email_verified', 'updated_at'])
                            
                            # Send verification email
                            if getattr(settings, 'REQUIRE_EMAIL_VERIFICATION', True):
                                send_email_verification(instance)
                            
                            logger.info(
                                f"User {instance.id} changed email from "
                                f"{old_user.email} to {instance.email}"
                            )
                        except UserProfile.DoesNotExist:
                            pass
                
                # Check if user was activated/deactivated
                if 'is_active' in update_fields:
                    action = "activated" if instance.is_active else "deactivated"
                    logger.info(f"User {instance.id} {action}")
                    
                    # Create audit event for activation/deactivation
                    SocialLoginEvent.objects.create(
                        user=instance,
                        event_type='login' if instance.is_active else 'error',
                        provider='system',
                        email_attempted=instance.email,
                        success=instance.is_active,
                        extra_data={'action': f'user_{action}'}
                    )
    
    except Exception as e:
        logger.error(
            f"Error in handle_user_creation for user {instance.id if instance else 'N/A'}: {e}",
            exc_info=True
        )


@receiver(pre_save, sender=User)
def pre_save_user_handler(sender, instance: User, **kwargs):
    """
    Handle pre-save operations for User model
    """
    try:
        # Clean and normalize data
        if instance.email:
            instance.email = instance.email.lower().strip()
        
        if instance.username:
            instance.username = instance.username.lower().strip()
        
        # Track if this is a new user (no PK yet)
        is_new = instance.pk is None
        
        if not is_new:
            # Get original user from database
            try:
                original = User.objects.get(pk=instance.pk)
                
                # Check if password was changed
                if instance.password != original.password:
                    # Password was changed - log and update profile
                    try:
                        profile = instance.profile
                        profile.updated_at = timezone.now()
                        profile.save(update_fields=['updated_at'])
                        
                        logger.info(f"User {instance.id} changed password")
                        
                        # Create audit event
                        SocialLoginEvent.objects.create(
                            user=instance,
                            event_type='connect',  # Reusing for password change
                            provider='local',
                            email_attempted=instance.email,
                            success=True,
                            extra_data={'action': 'password_changed'}
                        )
                    except UserProfile.DoesNotExist:
                        pass
                
                # Check if last_login was updated
                if original.last_login != instance.last_login and instance.last_login:
                    # Update profile's last_login_at
                    try:
                        profile = instance.profile
                        profile.last_login_at = instance.last_login
                        profile.save(update_fields=['last_login_at', 'updated_at'])
                    except UserProfile.DoesNotExist:
                        pass
            
            except User.DoesNotExist:
                # User doesn't exist yet (shouldn't happen in pre_save for existing)
                pass
        
    except Exception as e:
        logger.error(
            f"Error in pre_save_user_handler for user {instance.id if instance else 'N/A'}: {e}",
            exc_info=True
        )


@receiver(post_save, sender=UserProfile)
def handle_profile_update(sender, instance: UserProfile, created: bool, **kwargs):
    """
    Handle UserProfile updates and synchronize with User model
    """
    try:
        update_fields = kwargs.get('update_fields', set())
        
        if created:
            logger.info(f"UserProfile created for user {instance.user.id}")
            
            # Set default avatar if available
            if not instance.avatar and getattr(settings, 'DEFAULT_AVATAR_URL', None):
                # In production, you might want to download and save the avatar
                instance.extra_data = instance.extra_data or {}
                instance.extra_data['default_avatar'] = settings.DEFAULT_AVATAR_URL
                instance.save(update_fields=['extra_data'])
        
        else:
            # Handle specific field updates
            if 'department' in update_fields:
                # Department changed - log the change
                old_profile = UserProfile.objects.get(pk=instance.pk)
                if old_profile.department != instance.department:
                    old_dept = old_profile.department.name if old_profile.department else 'None'
                    new_dept = instance.department.name if instance.department else 'None'
                    
                    logger.info(
                        f"User {instance.user.id} department changed: "
                        f"{old_dept} -> {new_dept}"
                    )
            
            if 'identity_provider' in update_fields:
                # Identity provider changed
                logger.info(
                    f"User {instance.user.id} identity provider changed to: "
                    f"{instance.identity_provider}"
                )
        
        # Ensure email is synchronized
        if instance.user.email and not instance.user.email == instance.user.email.lower():
            instance.user.email = instance.user.email.lower()
            instance.user.save(update_fields=['email'])
    
    except Exception as e:
        logger.error(
            f"Error in handle_profile_update for profile {instance.id if instance else 'N/A'}: {e}",
            exc_info=True
        )


@receiver(m2m_changed, sender=User.groups.through)
def handle_user_group_changes(sender, instance: User, action: str, pk_set: set, **kwargs):
    """
    Handle user group membership changes
    """
    try:
        if action in ['post_add', 'post_remove', 'post_clear']:
            # Get group names
            groups = Group.objects.filter(pk__in=pk_set) if pk_set else []
            group_names = [g.name for g in groups]
            
            if action == 'post_add':
                logger.info(
                    f"User {instance.id} added to groups: {', '.join(group_names)}"
                )
                
                # Check for admin/staff groups
                admin_groups = getattr(settings, 'ADMIN_GROUPS', ['Administrators'])
                staff_groups = getattr(settings, 'STAFF_GROUPS', ['Staff', 'Managers'])
                
                for group_name in group_names:
                    if group_name in admin_groups:
                        instance.is_staff = True
                        instance.save(update_fields=['is_staff'])
                        logger.info(f"User {instance.id} granted staff status via group {group_name}")
                    
                    if group_name in staff_groups and not instance.is_staff:
                        instance.is_staff = True
                        instance.save(update_fields=['is_staff'])
                        logger.info(f"User {instance.id} granted staff status via group {group_name}")
            
            elif action == 'post_remove':
                logger.info(
                    f"User {instance.id} removed from groups: {', '.join(group_names)}"
                )
                
                # Check if user should lose staff status
                if instance.is_staff:
                    admin_groups = getattr(settings, 'ADMIN_GROUPS', ['Administrators'])
                    staff_groups = getattr(settings, 'STAFF_GROUPS', ['Staff', 'Managers'])
                    
                    # Check if user still has any admin/staff groups
                    user_admin_groups = instance.groups.filter(
                        name__in=admin_groups + staff_groups
                    ).exists()
                    
                    if not user_admin_groups:
                        instance.is_staff = False
                        instance.save(update_fields=['is_staff'])
                        logger.info(f"User {instance.id} lost staff status")
            
            # Create audit event
            SocialLoginEvent.objects.create(
                user=instance,
                event_type='connect',  # Reusing for group changes
                provider='system',
                email_attempted=instance.email,
                success=True,
                extra_data={
                    'action': f'groups_{action}',
                    'group_ids': list(pk_set) if pk_set else [],
                    'group_names': group_names
                }
            )
    
    except Exception as e:
        logger.error(
            f"Error in handle_user_group_changes for user {instance.id}: {e}",
            exc_info=True
        )


@receiver(pre_delete, sender=User)
def handle_user_deletion(sender, instance: User, **kwargs):
    """
    Handle user deletion - create backup and audit log
    """
    try:
        # Create audit log entry
        SocialLoginEvent.objects.create(
            user=None,  # User will be deleted
            event_type='disconnect',
            provider='system',
            email_attempted=instance.email,
            success=True,
            ip_address='system',
            extra_data={
                'action': 'user_deleted',
                'user_id': instance.id,
                'username': instance.username,
                'email': instance.email,
                'deleted_at': timezone.now().isoformat()
            }
        )
        
        # Archive user data if configured
        if getattr(settings, 'ARCHIVE_DELETED_USERS', False):
            archive_user_data(instance)
        
        logger.info(f"User deletion initiated: {instance.username} ({instance.email})")
    
    except Exception as e:
        logger.error(
            f"Error in handle_user_deletion for user {instance.id}: {e}",
            exc_info=True
        )


@receiver(post_delete, sender=User)
def post_delete_user_cleanup(sender, instance: User, **kwargs):
    """
    Clean up after user deletion
    """
    try:
        # Note: UserProfile should be deleted via CASCADE
        # SocialConnections should be deleted via CASCADE
        
        # Clean up any orphaned data
        # (Add any custom cleanup logic here)
        
        logger.info(f"User deletion completed: {instance.username}")
    
    except Exception as e:
        logger.error(
            f"Error in post_delete_user_cleanup for user {instance.id}: {e}",
            exc_info=True
        )


@receiver(post_save, sender=SocialConnection)
def handle_social_connection_change(sender, instance: SocialConnection, created: bool, **kwargs):
    """
    Update UserProfile when SocialConnection changes
    """
    try:
        if created:
            # New social connection - update UserProfile
            profile = instance.user.profile
            
            # Update identity provider if not set or this is primary
            if not profile.identity_provider or profile.identity_provider == 'local':
                profile.identity_provider = instance.identity_provider
                profile.external_id = instance.provider_id
                profile.save(update_fields=['identity_provider', 'external_id', 'updated_at'])
                
                logger.info(
                    f"Updated UserProfile identity provider for user {instance.user.id} "
                    f"to {instance.identity_provider} via {instance.provider}"
                )
        
        elif not instance.is_active:
            # Social connection deactivated
            profile = instance.user.profile
            
            # Check if this was the user's identity provider
            if profile.identity_provider == instance.identity_provider:
                # Find another active social connection
                other_connection = SocialConnection.objects.filter(
                    user=instance.user,
                    is_active=True
                ).exclude(id=instance.id).first()
                
                if other_connection:
                    profile.identity_provider = other_connection.identity_provider
                    profile.external_id = other_connection.provider_id
                else:
                    profile.identity_provider = 'local'
                    profile.external_id = ''
                
                profile.save(update_fields=['identity_provider', 'external_id', 'updated_at'])
                
                logger.info(
                    f"Updated UserProfile identity provider for user {instance.user.id} "
                    f"after deactivating {instance.provider}"
                )
    
    except Exception as e:
        logger.error(
            f"Error in handle_social_connection_change for connection {instance.id}: {e}",
            exc_info=True
        )


# Helper functions

def send_welcome_email_sync(user: User):
    """Send welcome email synchronously"""
    try:
        subject = getattr(settings, 'WELCOME_EMAIL_SUBJECT', 'Welcome to Our Platform')
        template = getattr(settings, 'WELCOME_EMAIL_TEMPLATE', 'users/emails/welcome.html')
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com')
        
        context = {
            'user': user,
            'site_name': getattr(settings, 'SITE_NAME', 'Our Platform'),
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@example.com'),
        }
        
        html_message = render_to_string(template, context)
        
        send_mail(
            subject=subject,
            message='',  # Plain text version can be generated from HTML
            html_message=html_message,
            from_email=from_email,
            recipient_list=[user.email],
            fail_silently=False,
        )
        
        logger.info(f"Welcome email sent to {user.email}")
        
    except Exception as e:
        logger.error(f"Failed to send welcome email to {user.email}: {e}")


def send_email_verification(user: User):
    """Send email verification link"""
    try:
        # Generate verification token (simplified)
        # In production, use a proper token generation library
        import hashlib
        import secrets
        
        token = secrets.token_urlsafe(32)
        verification_token = hashlib.sha256(
            f"{user.id}{user.email}{token}".encode()
        ).hexdigest()
        
        # Store token (in production, use a proper storage)
        profile = user.profile
        profile.extra_data = profile.extra_data or {}
        profile.extra_data['email_verification_token'] = verification_token
        profile.extra_data['email_verification_sent'] = timezone.now().isoformat()
        profile.save(update_fields=['extra_data'])
        
        # Send verification email
        subject = getattr(settings, 'VERIFICATION_EMAIL_SUBJECT', 'Verify Your Email Address')
        template = getattr(settings, 'VERIFICATION_EMAIL_TEMPLATE', 'users/emails/verify.html')
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com')
        
        context = {
            'user': user,
            'verification_url': f"{settings.FRONTEND_URL}/verify-email/{verification_token}/",
            'site_name': getattr(settings, 'SITE_NAME', 'Our Platform'),
        }
        
        html_message = render_to_string(template, context)
        
        send_mail(
            subject=subject,
            message='',
            html_message=html_message,
            from_email=from_email,
            recipient_list=[user.email],
            fail_silently=False,
        )
        
        logger.info(f"Verification email sent to {user.email}")
        
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {e}")


def archive_user_data(user: User):
    """Archive user data before deletion"""
    # This is a placeholder - implement proper archiving
    try:
        # Create archive record (simplified)
        # In production, use a proper archiving strategy
        logger.info(f"Archiving data for user {user.id}")
        
        # Example: Save to JSON file
        import json
        from django.core.serializers import serialize
        
        user_data = serialize('json', [user])
        profile_data = serialize('json', [user.profile]) if hasattr(user, 'profile') else '{}'
        
        archive = {
            'user': json.loads(user_data),
            'profile': json.loads(profile_data),
            'deleted_at': timezone.now().isoformat(),
        }
        
        # Save to file or database
        # (Implement proper archiving based on your requirements)
        
    except Exception as e:
        logger.error(f"Failed to archive data for user {user.id}: {e}")


def register_signals():
    """Explicitly register all signals"""
    # Signals are automatically registered via @receiver decorators
    # This function is for explicit initialization if needed
    logger.info("User management signals registered")