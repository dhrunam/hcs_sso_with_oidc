# apps/oidc/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from oauth2_provider.models import AccessToken
import logging

logger = logging.getLogger(__name__)

@receiver(post_save, sender=AccessToken)
def log_token_creation(sender, instance, created, **kwargs):
    """Log token creation for audit trail"""
    if created:
        logger.info(f"Access token created for user {instance.user_id} "
                   f"via client {instance.application.client_id}")