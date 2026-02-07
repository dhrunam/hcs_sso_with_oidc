# apps/users/tasks.py
"""
Celery tasks for user management (email sending, etc.)
"""

import logging
from celery import shared_task
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings

logger = logging.getLogger(__name__)

@shared_task
def send_welcome_email(user_id):
    """Send welcome email to new user"""
    try:
        user = User.objects.get(id=user_id)
        
        subject = getattr(settings, 'WELCOME_EMAIL_SUBJECT', 'Welcome to Our Platform')
        template = getattr(settings, 'WELCOME_EMAIL_TEMPLATE', 'users/emails/welcome.html')
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com')
        
        context = {
            'user': user,
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
        
        logger.info(f"Welcome email sent to {user.email} (async)")
        return True
        
    except User.DoesNotExist:
        logger.error(f"User {user_id} not found for welcome email")
        return False
    except Exception as e:
        logger.error(f"Failed to send welcome email to user {user_id}: {e}")
        return False

@shared_task
def send_password_reset_email(user_id, reset_token):
    """Send password reset email"""
    try:
        user = User.objects.get(id=user_id)
        
        # Similar implementation as welcome email
        # ...
        
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email: {e}")
        return False