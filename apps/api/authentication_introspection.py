"""
OIDC/OAuth2 Token Introspection Authentication for DRF.

This module provides an alternative JWT validation approach using OAuth2/OIDC
token introspection endpoint instead of validating JWTs locally.

Benefits:
- No need to fetch and cache JWKS
- Single source of truth: token validity checked at provider
- Immediate token revocation support
- Simpler key rotation handling

Tradeoff:
- Network call required for each request (higher latency)
- Requires introspection endpoint availability
- Cache needed to avoid overwhelming provider

Usage:
  from apps.api.authentication_introspection import OIDCTokenIntrospectionAuthentication
  
  REST_FRAMEWORK = {
      'DEFAULT_AUTHENTICATION_CLASSES': (
          'apps.api.authentication_introspection.OIDCTokenIntrospectionAuthentication',
          'rest_framework.authentication.SessionAuthentication',
      ),
  }
"""

import requests
import logging
import hashlib
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework import authentication, exceptions

logger = logging.getLogger(__name__)
User = get_user_model()


class TokenIntrospectionCache:
    """Simple cache wrapper for introspection results with TTL."""
    
    def __init__(self, ttl_seconds=300):  # Default 5 minutes
        self.ttl = ttl_seconds
    
    @staticmethod
    def _cache_key(token):
        """Generate cache key from token."""
        return f'token_introspection:{hashlib.sha256(token.encode()).hexdigest()}'
    
    def get(self, token):
        """Retrieve cached introspection result."""
        return cache.get(self._cache_key(token))
    
    def set(self, token, data):
        """Cache introspection result."""
        cache.set(self._cache_key(token), data, self.ttl)
    
    def invalidate(self, token):
        """Clear cached introspection result."""
        cache.delete(self._cache_key(token))


def introspect_token(token, use_cache=True):
    """
    Call the OAuth2 token introspection endpoint to validate a token.
    
    Args:
        token (str): The Bearer token to introspect
        use_cache (bool): Whether to use cached result
        
    Returns:
        dict: Introspection response including 'active', 'scope', 'client_id', 'sub', etc.
        
    Raises:
        requests.RequestException: If introspection endpoint unreachable
        ValueError: If token is inactive
    """
    cache_mgr = TokenIntrospectionCache(ttl_seconds=getattr(settings, 'TOKEN_INTROSPECTION_CACHE_TTL', 300))
    
    # Check cache first
    if use_cache:
        cached = cache_mgr.get(token)
        if cached:
            logger.debug("Using cached token introspection result")
            return cached
    
    introspection_url = settings.SSO_INTROSPECTION_URL  # e.g., http://sso.example.com/o/introspect/
    
    payload = {
        'token': token,
        'client_id': settings.SSO_CLIENT_ID,
        'client_secret': settings.SSO_CLIENT_SECRET,
    }
    
    try:
        response = requests.post(introspection_url, data=payload, timeout=5)
        response.raise_for_status()
        result = response.json()
        
        # Check if token is active
        if not result.get('active', False):
            logger.warning("Token introspection returned inactive status")
            raise ValueError("Token is inactive or revoked")
        
        # Cache the result
        if use_cache:
            cache_mgr.set(token, result)
        
        return result
        
    except requests.RequestException as e:
        logger.error(f"Token introspection failed: {e}")
        raise
    except ValueError as e:
        logger.warning(f"Token validation failed: {e}")
        raise


class OIDCTokenIntrospectionAuthentication(authentication.BaseAuthentication):
    """
    DRF authentication class using OAuth2 token introspection.
    
    Validates Bearer tokens by calling the OAuth2 introspection endpoint
    instead of validating JWTs locally. Provides immediate revocation support
    and simplified key management.
    
    Token claims are extracted from the introspection response and used to:
    - Map to a Django User instance (by sub, email, or preferred_username)
    - Extract scopes and roles for permission checks
    - Cache results for performance
    
    Requires settings:
    - SSO_INTROSPECTION_URL: Introspection endpoint URL
    - SSO_CLIENT_ID: OAuth2 client ID
    - SSO_CLIENT_SECRET: OAuth2 client secret
    """
    
    www_authenticate_realm = 'api'
    
    def authenticate(self, request):
        """
        Authenticate request using Bearer token introspection.
        
        Args:
            request: DRF Request object
            
        Returns:
            (user, token) tuple if authenticated, None if no token present
            
        Raises:
            AuthenticationFailed: If token is invalid/inactive
        """
        auth = authentication.get_authorization_header(request).split()
        
        if not auth or auth[0].lower() != b'bearer':
            return None
        
        if len(auth) == 1:
            msg = 'Invalid token header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        
        if len(auth) > 2:
            msg = 'Invalid token header. Token string should not contain spaces.'
            raise exceptions.AuthenticationFailed(msg)
        
        token = auth[1].decode('utf-8')
        
        try:
            # Introspect the token at the provider
            claims = introspect_token(token, use_cache=True)
        except ValueError as e:
            raise exceptions.AuthenticationFailed(f'Token validation failed: {str(e)}')
        except requests.RequestException as e:
            logger.error(f'Introspection endpoint error: {e}')
            raise exceptions.AuthenticationFailed('Could not validate token')
        
        # Map claims to Django User
        user = self._get_or_create_user(claims)
        
        # Optionally store claims in request for use in views/permissions
        request.token_claims = claims
        request.token_scopes = claims.get('scope', '').split()
        
        return (user, token)
    
    def _get_or_create_user(self, claims):
        """
        Map introspection claims to a Django User instance.
        
        Lookup order:
        1. By numeric 'sub' as user_id
        2. By 'email' claim
        3. By 'preferred_username' claim
        
        Auto-provisions user if not found and enabled.
        
        Args:
            claims (dict): Token introspection claims
            
        Returns:
            User: Django User instance
            
        Raises:
            AuthenticationFailed: If user not found and auto-provision disabled
        """
        sub = claims.get('sub')
        email = claims.get('email')
        preferred_username = claims.get('preferred_username')
        
        user = None
        
        # Try numeric sub first (mapping to user_id)
        if sub and str(sub).isdigit():
            try:
                user = User.objects.get(pk=int(sub))
                logger.debug(f"User authenticated by sub={sub}")
                return user
            except User.DoesNotExist:
                pass
        
        # Try email
        if email:
            user = User.objects.filter(email__iexact=email).first()
            if user:
                logger.debug(f"User authenticated by email={email}")
                return user
        
        # Try preferred_username
        if preferred_username:
            user = User.objects.filter(username__iexact=preferred_username).first()
            if user:
                logger.debug(f"User authenticated by preferred_username={preferred_username}")
                return user
        
        # Not found: auto-provision if enabled
        if getattr(settings, 'SSO_AUTO_PROVISION_USER', False):
            logger.info(f"Auto-provisioning user from claims: sub={sub}, email={email}")
            user = self._provision_user(claims)
            return user
        
        # Not found and no auto-provision
        raise exceptions.AuthenticationFailed(
            'User not found and auto-provisioning is disabled'
        )
    
    def _provision_user(self, claims):
        """
        Create a new Django User from token claims.
        
        Args:
            claims (dict): Token introspection claims
            
        Returns:
            User: Newly created Django User instance
        """
        sub = claims.get('sub')
        email = claims.get('email', f'user_{sub}@sso.example.com')
        first_name = claims.get('given_name', '')
        last_name = claims.get('family_name', '')
        preferred_username = claims.get('preferred_username', email.split('@')[0])
        
        user = User.objects.create_user(
            username=preferred_username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            is_active=True,
        )
        
        logger.info(f"Provisioned new user {user.id} from OIDC claims")
        return user
    
    def authenticate_header(self, request):
        """Return WWW-Authenticate header for 401 responses."""
        return self.www_authenticate_realm


class IntrospectionCacheInvalidationMixin:
    """
    Mixin for views that need to invalidate cached introspection results.
    
    Usage:
        class LogoutView(IntrospectionCacheInvalidationMixin, APIView):
            def post(self, request):
                token = authentication.get_authorization_header(request)
                self.invalidate_token_cache(token)
                ...
    """
    
    def invalidate_token_cache(self, auth_header):
        """
        Clear cached introspection for a token.
        
        Args:
            auth_header (bytes): Authorization header value
        """
        try:
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == b'bearer':
                token = parts[1].decode('utf-8')
                cache_mgr = TokenIntrospectionCache()
                cache_mgr.invalidate(token)
                logger.debug("Invalidated token introspection cache")
        except Exception as e:
            logger.warning(f"Failed to invalidate cache: {e}")
