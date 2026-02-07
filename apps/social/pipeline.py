# apps/social/pipeline.py
"""
Social authentication pipeline functions for customizing the authentication flow.
These functions are executed in sequence during social authentication.
"""

import logging
from typing import Dict, Any, Optional
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import Group
from django.db import transaction
from social_core.pipeline.social_auth import social_details
from social_core.exceptions import AuthForbidden, AuthCanceled
from apps.core.models import UserProfile, Department, Organization
from apps.social.models import SocialConnection, SocialLoginEvent

logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_SOCIAL_GROUP = getattr(settings, 'SOCIAL_AUTH_DEFAULT_GROUP', 'social_users')
DEFAULT_REDIRECT_URL = getattr(settings, 'SOCIAL_AUTH_LOGIN_REDIRECT_URL', '/')
PROFILE_COMPLETE_URL = getattr(settings, 'SOCIAL_AUTH_PROFILE_COMPLETE_URL', '/profile/complete/')
ALLOWED_EMAIL_DOMAINS = getattr(settings, 'SOCIAL_AUTH_ALLOWED_DOMAINS', [])


# ==================== HELPER FUNCTIONS ====================

def get_provider_display_name(backend_name: str) -> str:
    """Get user-friendly display name for a provider"""
    provider_map = {
        'google-oauth2': 'Google',
        'facebook': 'Facebook',
        'github': 'GitHub',
        'microsoft-graph': 'Microsoft',
        'linkedin': 'LinkedIn',
        'azuread-oauth2': 'Azure AD',
        'okta-oauth2': 'Okta',
        'openid-connect': 'OpenID Connect',
        'apple-id': 'Apple',
        'slack': 'Slack',
        'discord': 'Discord',
        'twitter': 'Twitter',
    }
    return provider_map.get(backend_name, backend_name.replace('-', ' ').title())


def extract_user_data(backend_name: str, response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract standardized user data from provider response
    
    Args:
        backend_name: Name of the social backend
        response: Raw response from the provider
    
    Returns:
        Dictionary with standardized user data
    """
    data = {
        'email': '',
        'first_name': '',
        'last_name': '',
        'full_name': '',
        'picture_url': '',
        'locale': '',
        'timezone': '',
        'email_verified': False,
        'extra_data': {},
    }
    
    # Common field mappings across providers
    field_mappings = {
        'email': ['email', 'mail', 'userPrincipalName', 'upn'],
        'first_name': ['given_name', 'givenName', 'first_name', 'firstName', 'firstname'],
        'last_name': ['family_name', 'familyName', 'last_name', 'lastName', 'lastname'],
        'full_name': ['name', 'displayName', 'full_name', 'fullName'],
        'picture_url': ['picture', 'avatar_url', 'avatarUrl', 'photoURL', 'profilePicture'],
        'locale': ['locale', 'language', 'preferred_language'],
        'timezone': ['timezone', 'zoneinfo', 'timeZone'],
        'email_verified': ['email_verified', 'verified_email', 'verified'],
    }
    
    # Extract using field mappings
    for field, possible_keys in field_mappings.items():
        for key in possible_keys:
            if key in response and response[key]:
                if field == 'picture_url' and isinstance(response[key], dict):
                    # Handle nested picture structures (Facebook, LinkedIn)
                    if 'data' in response[key] and 'url' in response[key]['data']:
                        data[field] = response[key]['data']['url']
                    elif 'displayImage~' in response[key]:
                        elements = response[key]['displayImage~'].get('elements', [])
                        if elements and 'identifiers' in elements[0]:
                            data[field] = elements[0]['identifiers'][0].get('identifier', '')
                else:
                    data[field] = response[key]
                break
    
    # Provider-specific data extraction
    if backend_name == 'google-oauth2':
        data['extra_data'].update({
            'google_id': response.get('sub'),
            'hd': response.get('hd'),  # Google Apps domain
            'locale': response.get('locale'),
        })
        if 'email_verified' in response:
            data['email_verified'] = bool(response['email_verified'])
    
    elif backend_name == 'facebook':
        data['extra_data'].update({
            'facebook_id': response.get('id'),
            'gender': response.get('gender'),
            'timezone_offset': response.get('timezone'),
        })
    
    elif backend_name == 'microsoft-graph':
        data['extra_data'].update({
            'microsoft_id': response.get('id'),
            'job_title': response.get('jobTitle'),
            'office_location': response.get('officeLocation'),
            'mobile_phone': response.get('mobilePhone'),
        })
    
    elif backend_name == 'github':
        data['extra_data'].update({
            'github_id': response.get('id'),
            'company': response.get('company'),
            'blog': response.get('blog'),
            'location': response.get('location'),
            'hireable': response.get('hireable'),
        })
    
    elif backend_name == 'linkedin':
        data['extra_data'].update({
            'linkedin_id': response.get('id'),
            'headline': response.get('headline', ''),
            'industry': response.get('industry', ''),
        })
    
    elif backend_name in ['azuread-oauth2', 'okta-oauth2', 'openid-connect']:
        # OIDC providers
        data['extra_data'].update({
            'oidc_id': response.get('sub'),
            'issuer': response.get('iss'),
            'audience': response.get('aud'),
        })
        if 'email_verified' in response:
            data['email_verified'] = bool(response['email_verified'])
    
    return data


def validate_email_domain(email: str, backend_name: str) -> bool:
    """
    Validate email domain against allowed domains
    
    Args:
        email: User email address
        backend_name: Social backend name for logging
    
    Returns:
        True if email domain is allowed
    """
    if not email:
        logger.warning(f"No email provided for {backend_name} authentication")
        return False
    
    if not ALLOWED_EMAIL_DOMAINS:
        return True  # No restrictions
    
    domain = email.split('@')[-1].lower() if '@' in email else ''
    
    if domain not in ALLOWED_EMAIL_DOMAINS:
        logger.warning(
            f"Email domain {domain} not allowed for {backend_name}. "
            f"Allowed domains: {ALLOWED_EMAIL_DOMAINS}"
        )
        return False
    
    return True


# ==================== PIPELINE FUNCTIONS ====================

def validate_social_auth(backend, details, response, *args, **kwargs):
    """
    Validate social authentication before proceeding
    
    This runs early in the pipeline to reject invalid authentications
    """
    backend_name = backend.name
    email = details.get('email') or response.get('email') or response.get('mail')
    
    # Log authentication attempt
    logger.info(f"Social auth attempt via {backend_name} for email: {email}")
    
    # Validate email domain
    if email and not validate_email_domain(email, backend_name):
        raise AuthForbidden(backend, f"Email domain not allowed for {get_provider_display_name(backend_name)}")
    
    # Check if user is already banned/blocked (extend as needed)
    # You could check against a blacklist here
    
    return {'details': details, 'response': response}


def extract_and_normalize_data(backend, details, response, *args, **kwargs):
    """
    Extract and normalize user data from social provider response
    """
    try:
        backend_name = backend.name
        user_data = extract_user_data(backend_name, response)
        
        # Update details with normalized data
        if user_data['email']:
            details['email'] = user_data['email']
        if user_data['first_name']:
            details['first_name'] = user_data['first_name']
        if user_data['last_name']:
            details['last_name'] = user_data['last_name']
        
        # Store extracted data for later pipeline steps
        return {
            'details': details,
            'user_data': user_data,
            'backend_name': backend_name,
        }
    
    except Exception as e:
        logger.error(f"Failed to extract user data from {backend.name}: {e}")
        # Don't raise - let authentication continue with available data
        return {'details': details, 'user_data': {}}


def create_or_update_user_profile(strategy, details, backend, user=None, *args, **kwargs):
    """
    Create or update user profile with social auth data
    
    This runs after the user is created/retrieved by social_core
    """
    try:
        if not user:
            return {'user': None}
        
        user_data = kwargs.get('user_data', {})
        backend_name = kwargs.get('backend_name', backend.name)
        response = kwargs.get('response', {})
        
        with transaction.atomic():
            # Get or create UserProfile
            profile, created = UserProfile.objects.get_or_create(user=user)
            
            # Update identity provider info
            profile.identity_provider = backend_name
            profile.external_id = kwargs.get('uid') or response.get('id') or response.get('sub')
            
            # Update email verification status
            if user_data.get('email_verified'):
                profile.email_verified = True
            
            # Update locale and timezone if available
            if user_data.get('locale'):
                profile.preferred_language = user_data['locale'][:10]
            
            if user_data.get('timezone'):
                profile.timezone = user_data['timezone'][:50]
            
            # Handle avatar (store URL or download image)
            if user_data.get('picture_url'):
                # For now, we'll store the URL in extra_data
                # In production, you might want to download and store the image
                extra_data = profile.extra_data or {}
                extra_data['avatar_url'] = user_data['picture_url']
                profile.extra_data = extra_data
            
            # Update last login
            profile.last_login_at = timezone.now()
            
            profile.save()
            
            # Update user basic info if not already set
            update_fields = []
            if user_data.get('first_name') and not user.first_name:
                user.first_name = user_data['first_name'][:30]
                update_fields.append('first_name')
            
            if user_data.get('last_name') and not user.last_name:
                user.last_name = user_data['last_name'][:30]
                update_fields.append('last_name')
            
            if user_data.get('email') and not user.email:
                user.email = user_data['email']
                update_fields.append('email')
            
            if update_fields:
                user.save(update_fields=update_fields)
            
            action = "Created" if created else "Updated"
            logger.info(f"{action} UserProfile for {user.email} via {backend_name}")
            
            return {'user': user, 'profile': profile, 'profile_created': created}
    
    except Exception as e:
        logger.error(f"Failed to create/update UserProfile for user {user.id if user else 'N/A'}: {e}")
        # Don't raise - authentication should still succeed
        return {'user': user}


def create_social_connection_record(strategy, details, backend, user=None, social=None, *args, **kwargs):
    """
    Create or update SocialConnection record
    
    This creates our SocialConnection model entry linked to UserSocialAuth
    """
    try:
        if not user or not social:
            return {'user': user}
        
        user_data = kwargs.get('user_data', {})
        backend_name = kwargs.get('backend_name', backend.name)
        
        # Extract tokens from social object
        access_token = social.extra_data.get('access_token', '')
        refresh_token = social.extra_data.get('refresh_token', '')
        
        # Calculate token expiry if available
        token_expiry = None
        expires_in = social.extra_data.get('expires_in')
        if expires_in:
            token_expiry = timezone.now() + timezone.timedelta(seconds=expires_in)
        
        # Create or update SocialConnection
        connection, created = SocialConnection.objects.update_or_create(
            social_auth=social,
            defaults={
                'user': user,
                'provider': backend_name,
                'provider_id': social.uid,
                'email': user.email or user_data.get('email', ''),
                'name': user.get_full_name() or user_data.get('full_name', ''),
                'picture_url': user_data.get('picture_url', ''),
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_expiry': token_expiry,
                'extra_data': user_data.get('extra_data', {}),
                'is_active': True,
                'last_used': timezone.now(),
            }
        )
        
        # Set as primary if first connection
        if created:
            other_connections = SocialConnection.objects.filter(
                user=user, is_active=True
            ).exclude(id=connection.id).count()
            
            if other_connections == 0:
                connection.is_primary = True
                connection.save(update_fields=['is_primary'])
        
        # Create audit log entry
        SocialLoginEvent.objects.create(
            user=user,
            event_type='connect' if created else 'reconnect',
            provider=backend_name,
            provider_id=social.uid,
            email_attempted=user.email or user_data.get('email', ''),
            success=True,
            ip_address=strategy.request.META.get('REMOTE_ADDR', ''),
            user_agent=strategy.request.META.get('HTTP_USER_AGENT', ''),
            extra_data={
                'action': 'created' if created else 'updated',
                'social_auth_id': social.id,
                'provider_display': get_provider_display_name(backend_name)
            }
        )
        
        action = "created" if created else "updated"
        logger.info(f"SocialConnection {action} for user {user.email} via {backend_name}")
        
        return {'user': user, 'social_connection': connection}
    
    except Exception as e:
        logger.error(f"Failed to create SocialConnection for user {user.id if user else 'N/A'}: {e}")
        return {'user': user}


def assign_default_groups_and_permissions(strategy, details, backend, user=None, is_new=False, *args, **kwargs):
    """
    Assign default groups and permissions to new social auth users
    
    Args:
        is_new: Boolean indicating if this is a new user
    """
    if not user or not is_new:
        return {'user': user}
    
    try:
        backend_name = kwargs.get('backend_name', backend.name)
        
        # Assign to default social users group
        if DEFAULT_SOCIAL_GROUP:
            group, created = Group.objects.get_or_create(name=DEFAULT_SOCIAL_GROUP)
            user.groups.add(group)
            logger.debug(f"Added user {user.email} to {DEFAULT_SOCIAL_GROUP} group")
        
        # Assign provider-specific group
        provider_group_name = f"{backend_name}_users"
        provider_group, created = Group.objects.get_or_create(name=provider_group_name)
        user.groups.add(provider_group)
        
        # Auto-activate user if configured
        auto_activate = getattr(settings, 'SOCIAL_AUTH_AUTO_ACTIVATE', True)
        if auto_activate and not user.is_active:
            user.is_active = True
            user.save(update_fields=['is_active'])
            logger.info(f"Auto-activated user {user.email}")
        
        # Assign department based on email domain (if configured)
        auto_assign_department = getattr(settings, 'SOCIAL_AUTH_AUTO_ASSIGN_DEPARTMENT', False)
        if auto_assign_department and user.email:
            try:
                domain = user.email.split('@')[-1].lower()
                
                # Try to find organization by domain
                org = Organization.objects.filter(domain__icontains=domain).first()
                if org:
                    # Find or create external users department
                    dept, created = Department.objects.get_or_create(
                        organization=org,
                        name='External Users',
                        defaults={
                            'code': 'EXT',
                            'description': f'External users from {backend_name}'
                        }
                    )
                    
                    # Update user profile
                    profile = UserProfile.objects.filter(user=user).first()
                    if profile:
                        profile.department = dept
                        profile.save(update_fields=['department'])
                        
                        logger.info(f"Assigned department {dept.name} to user {user.email}")
            
            except Exception as e:
                logger.warning(f"Could not auto-assign department for {user.email}: {e}")
        
        logger.info(f"Assigned default groups for new user {user.email} via {backend_name}")
        
        return {'user': user}
    
    except Exception as e:
        logger.error(f"Failed to assign default groups for user {user.id}: {e}")
        return {'user': user}


def handle_new_user_redirect(strategy, details, backend, user=None, is_new=False, *args, **kwargs):
    """
    Handle redirect URL for new vs returning users
    
    New users might be redirected to profile completion
    """
    if not user:
        return {}
    
    try:
        request = strategy.request if hasattr(strategy, 'request') else None
        
        if is_new:
            # New users go to profile completion
            redirect_url = PROFILE_COMPLETE_URL
            
            # Store in session for post-login redirect
            if request:
                request.session['social_auth_redirect'] = redirect_url
                request.session['social_auth_is_new'] = True
                request.session['social_auth_provider'] = backend.name
            
            logger.info(f"New user {user.email} will be redirected to profile completion")
        
        else:
            # Returning users go to default redirect
            redirect_url = DEFAULT_REDIRECT_URL
            
            # Check if user needs to complete profile
            profile_complete = True
            try:
                profile = user.profile
                if not profile.phone_number or not profile.job_title:
                    profile_complete = False
            except (UserProfile.DoesNotExist, AttributeError):
                profile_complete = False
            
            if not profile_complete:
                redirect_url = PROFILE_COMPLETE_URL
            
            if request:
                request.session['social_auth_redirect'] = redirect_url
                request.session['social_auth_is_new'] = False
        
        return {'redirect_url': redirect_url}
    
    except Exception as e:
        logger.error(f"Failed to determine redirect URL for user {user.id}: {e}")
        return {}


def log_social_login_success(strategy, details, backend, user=None, *args, **kwargs):
    """
    Log successful social login for audit and analytics
    """
    try:
        if not user:
            return {'user': None}
        
        backend_name = kwargs.get('backend_name', backend.name)
        request = strategy.request if hasattr(strategy, 'request') else None
        
        # Create detailed login event
        SocialLoginEvent.objects.create(
            user=user,
            event_type='login',
            provider=backend_name,
            provider_id=kwargs.get('uid', ''),
            email_attempted=user.email or details.get('email', ''),
            success=True,
            ip_address=request.META.get('REMOTE_ADDR') if request else '',
            user_agent=request.META.get('HTTP_USER_AGENT', '') if request else '',
            referer=request.META.get('HTTP_REFERER', '') if request else '',
            extra_data={
                'provider_display': get_provider_display_name(backend_name),
                'strategy': strategy.__class__.__name__,
                'is_new': kwargs.get('is_new', False),
            }
        )
        
        # Update last login time in profile
        try:
            profile = user.profile
            profile.last_login_at = timezone.now()
            profile.save(update_fields=['last_login_at'])
        except (UserProfile.DoesNotExist, AttributeError):
            pass
        
        logger.info(f"Successful social login for {user.email} via {backend_name}")
        
        return {'user': user}
    
    except Exception as e:
        logger.error(f"Failed to log social login success for user {user.id if user else 'N/A'}: {e}")
        return {'user': user}


def cleanup_social_session(strategy, *args, **kwargs):
    """
    Clean up social auth session data after successful authentication
    
    This runs at the end of the pipeline
    """
    try:
        request = strategy.request if hasattr(strategy, 'request') else None
        if request:
            # Clean up temporary session data
            keys_to_remove = [
                'partial_pipeline',
                'social_extra_data',
                'social_auth_last_backend',
            ]
            
            for key in keys_to_remove:
                if key in request.session:
                    del request.session[key]
            
            logger.debug("Cleaned up social auth session data")
    
    except Exception as e:
        logger.warning(f"Failed to clean up social session: {e}")
    
    return {}


# ==================== PIPELINE CONFIGURATION ====================

# Define the pipeline order
SOCIAL_AUTH_PIPELINE = (
    # Built-in social_core pipelines
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.auth_allowed',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    'social_core.pipeline.social_auth.associate_by_email',
    'social_core.pipeline.user.create_user',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
    
    # Custom pipelines
    'apps.social.pipeline.validate_social_auth',
    'apps.social.pipeline.extract_and_normalize_data',
    'apps.social.pipeline.create_or_update_user_profile',
    'apps.social.pipeline.create_social_connection_record',
    'apps.social.pipeline.assign_default_groups_and_permissions',
    'apps.social.pipeline.handle_new_user_redirect',
    'apps.social.pipeline.log_social_login_success',
    'apps.social.pipeline.cleanup_social_session',
)