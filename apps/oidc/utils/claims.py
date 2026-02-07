# apps/oidc/utils/claims.py
from django.utils import timezone
from django.core.cache import cache
from apps.core.models import UserProfile
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def get_user_profile(user):
    """
    Get user profile with caching
    """
    cache_key = f"user_profile_{user.id}"
    profile = cache.get(cache_key)
    
    if profile is None:
        try:
            # Use select_related to optimize database queries
            profile = UserProfile.objects.select_related(
                'department__organization'
            ).get(user=user)
            # Cache for 5 minutes
            cache.set(cache_key, profile, timeout=300)
        except UserProfile.DoesNotExist:
            logger.warning(f"No profile found for user {user.id}")
            profile = None
    
    return profile


def get_standard_profile_claims(user, profile=None, include_picture_url=None):
    """
    Get standard OIDC profile claims
    
    Args:
        user: Django User object
        profile: UserProfile object (optional, will be fetched if not provided)
        include_picture_url: Request object for building absolute URL (optional)
    """
    if profile is None:
        profile = get_user_profile(user)
    
    claims = {
        'name': f'{user.first_name} {user.last_name}'.strip() or user.username,
        'given_name': user.first_name,
        'family_name': user.last_name,
        'preferred_username': user.username,
        'updated_at': int(
            (user.last_login if user.last_login else user.date_joined).timestamp()
        ),
    }
    
    # Add picture if available
    if profile and profile.avatar and include_picture_url:
        try:
            if hasattr(profile.avatar, 'url'):
                claims['picture'] = include_picture_url.build_absolute_uri(profile.avatar.url)
        except (ValueError, AttributeError) as e:
            logger.error(f"Error generating avatar URL: {e}")
    
    return claims


def get_email_claims(user, profile=None):
    """
    Get standard OIDC email claims
    
    Args:
        user: Django User object
        profile: UserProfile object (optional, will be fetched if not provided)
    """
    if profile is None:
        profile = get_user_profile(user)
    
    return {
        'email': user.email,
        'email_verified': profile.email_verified if profile else False,
    }


def get_phone_claims(profile):
    """
    Get standard OIDC phone claims
    
    Args:
        profile: UserProfile object
    """
    if not profile or not profile.phone_number:
        return {}
    
    return {
        'phone_number': profile.phone_number,
        'phone_number_verified': False,  # You could add this as a profile field
    }


def get_address_claims(profile):
    """
    Get standard OIDC address claims
    
    Args:
        profile: UserProfile object
    """
    # Note: You need to add address fields to UserProfile first
    # Example fields: street_address, locality, region, postal_code, country
    if not profile:
        return {}
    
    address_claims = {}
    
    # Example implementation if you add these fields:
    # if profile.street_address:
    #     address_claims['address'] = {
    #         'street_address': profile.street_address,
    #         'locality': profile.locality or '',
    #         'region': profile.region or '',
    #         'postal_code': profile.postal_code or '',
    #         'country': profile.country or '',
    #     }
    
    return address_claims


def get_organization_claims(profile):
    """
    Get custom organization/department claims
    
    Args:
        profile: UserProfile object
    """
    if not profile:
        return {
            'identity_provider': 'local',
        }
    
    claims = {
        'identity_provider': profile.identity_provider,
    }
    
    # Department and organization claims
    if profile.department and profile.department.organization:
        claims.update({
            'organization': profile.department.organization.name,
            'organization_domain': profile.department.organization.domain,
            'department': profile.department.code,
            'department_name': profile.department.name,
        })
    
    # Employee ID
    if profile.employee_id:
        claims['employee_id'] = profile.employee_id
    
    # Job title
    if profile.job_title:
        claims['job_title'] = profile.job_title
    
    return claims


def get_locale_claims(profile):
    """
    Get locale and timezone claims
    
    Args:
        profile: UserProfile object
    """
    if not profile:
        return {}
    
    claims = {}
    
    if profile.preferred_language:
        claims['locale'] = profile.preferred_language
    
    if profile.timezone:
        claims['zoneinfo'] = profile.timezone
    
    return claims


def get_user_claims(user, scopes, request=None):
    """
    Get all claims for a user based on requested scopes
    
    Args:
        user: Django User object
        scopes: List of requested scopes
        request: Request object (for building absolute URLs)
    """
    scopes_set = set(scopes)
    profile = get_user_profile(user)
    
    claims = {
        'sub': str(user.id),
        'auth_time': int(timezone.now().timestamp()),
    }
    
    # Always include identity provider
    claims['identity_provider'] = profile.identity_provider if profile else 'local'
    
    # Profile scope
    if 'profile' in scopes_set:
        claims.update(get_standard_profile_claims(user, profile, request))
    
    # Email scope
    if 'email' in scopes_set:
        claims.update(get_email_claims(user, profile))
    
    # Phone scope
    if 'phone' in scopes_set:
        claims.update(get_phone_claims(profile))
    
    # Address scope
    if 'address' in scopes_set:
        claims.update(get_address_claims(profile))
    
    # Custom/Organization scopes
    if any(scope in scopes_set for scope in ['custom', 'org', 'organizational']):
        claims.update(get_organization_claims(profile))
    
    # Locale claims
    if 'locale' in scopes_set or 'zoneinfo' in scopes_set:
        claims.update(get_locale_claims(profile))
    
    return claims


def get_userinfo_claims(user, scopes, request=None):
    """
    Get claims for userinfo endpoint (subset of user claims)
    
    Args:
        user: Django User object
        scopes: List of requested scopes
        request: Request object (for building absolute URLs)
    """
    scopes_set = set(scopes)
    profile = get_user_profile(user)
    
    claims = {'sub': str(user.id)}
    
    # Profile scope
    if 'profile' in scopes_set:
        claims.update(get_standard_profile_claims(user, profile, request))
    
    # Email scope
    if 'email' in scopes_set:
        claims.update(get_email_claims(user, profile))
    
    # Phone scope
    if 'phone' in scopes_set:
        claims.update(get_phone_claims(profile))
    
    # Address scope
    if 'address' in scopes_set:
        claims.update(get_address_claims(profile))
    
    # Custom/Organization scopes
    if any(scope in scopes_set for scope in ['custom', 'org', 'organizational']):
        claims.update(get_organization_claims(profile))
    
    # Locale claims
    if 'locale' in scopes_set:
        locale_claims = get_locale_claims(profile)
        if 'locale' in locale_claims:
            claims['locale'] = locale_claims['locale']
    
    if 'zoneinfo' in scopes_set:
        locale_claims = get_locale_claims(profile)
        if 'zoneinfo' in locale_claims:
            claims['zoneinfo'] = locale_claims['zoneinfo']
    
    return claims


def validate_claims_request(requested_claims, available_scopes):
    """
    Validate requested claims against available scopes
    
    Args:
        requested_claims: Dict of requested claims (from claims parameter)
        available_scopes: List of granted scopes
    
    Returns:
        Tuple of (valid, error_message)
    """
    # Map claims to required scopes
    claim_to_scope = {
        'name': 'profile',
        'given_name': 'profile',
        'family_name': 'profile',
        'preferred_username': 'profile',
        'picture': 'profile',
        'email': 'email',
        'email_verified': 'email',
        'phone_number': 'phone',
        'phone_number_verified': 'phone',
        'address': 'address',
        'organization': 'org',
        'department': 'org',
        'employee_id': 'org',
        'locale': 'locale',
        'zoneinfo': 'zoneinfo',
    }
    
    available_scopes_set = set(available_scopes)
    
    for claim in requested_claims:
        if claim in claim_to_scope:
            required_scope = claim_to_scope[claim]
            if required_scope not in available_scopes_set:
                return False, f"Claim '{claim}' requires scope '{required_scope}'"
    
    return True, None


def filter_claims_by_scope(claims, scopes):
    """
    Filter claims dictionary based on granted scopes
    
    Args:
        claims: Full claims dictionary
        scopes: List of granted scopes
    
    Returns:
        Filtered claims dictionary
    """
    scopes_set = set(scopes)
    
    # Define which claims belong to which scopes
    scope_claims = {
        'profile': ['name', 'given_name', 'family_name', 'preferred_username', 
                   'picture', 'updated_at'],
        'email': ['email', 'email_verified'],
        'phone': ['phone_number', 'phone_number_verified'],
        'address': ['address'],
        'org': ['organization', 'department', 'employee_id', 'job_title', 
               'identity_provider'],
        'locale': ['locale'],
        'zoneinfo': ['zoneinfo'],
    }
    
    # Always include these claims
    always_include = ['sub']
    
    filtered_claims = {}
    
    # Include always-included claims
    for claim in always_include:
        if claim in claims:
            filtered_claims[claim] = claims[claim]
    
    # Include scope-based claims
    for scope, scope_claim_list in scope_claims.items():
        if scope in scopes_set:
            for claim in scope_claim_list:
                if claim in claims and claims[claim] is not None:
                    filtered_claims[claim] = claims[claim]
    
    return filtered_claims