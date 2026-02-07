# apps/social/signals.py
import logging
from django.db.models.signals import post_save
from django.dispatch import receiver
from social_django.models import UserSocialAuth
from apps.core.models import UserProfile
from django.contrib.auth.models import User

logger = logging.getLogger(__name__)

@receiver(post_save, sender=UserSocialAuth)
def update_user_profile_from_social_auth(sender, instance, created, **kwargs):
    """
    Update user profile when social auth is created/updated
    """
    try:
        user = instance.user
        provider = instance.provider
        
        # Get or create user profile
        profile, created_profile = UserProfile.objects.get_or_create(
            user=user,
            defaults={
                'identity_provider': provider,
                'external_id': instance.uid,
            }
        )
        
        if not created_profile:
            # Update existing profile
            profile.identity_provider = provider
            profile.external_id = instance.uid
            profile.save(update_fields=['identity_provider', 'external_id', 'updated_at'])
            
            logger.info(f"Updated profile for user {user.id} from {provider}")
        else:
            logger.info(f"Created profile for user {user.id} from {provider}")
            
    except Exception as e:
        logger.error(f"Failed to update profile from social auth: {e}")


@receiver(post_save, sender=User)
def create_user_profile_on_user_creation(sender, instance, created, **kwargs):
    """
    Create user profile when a new user is created
    """
    if created and not hasattr(instance, 'profile'):
        try:
            UserProfile.objects.create(user=instance)
            logger.debug(f"Created profile for new user {instance.id}")
        except Exception as e:
            logger.error(f"Failed to create profile for new user: {e}")