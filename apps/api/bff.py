"""
Backend-for-Frontend (BFF) views for secure OAuth2/OIDC token management.

The BFF pattern adds a backend layer that handles:
1. OAuth2 authorization code exchange (never exposed to browser)
2. Refresh token storage in HTTP-only cookies (not accessible to JavaScript)
3. Access token provisioning to the Angular frontend
4. Token refresh lifecycle management

This keeps sensitive tokens server-side and provides a security boundary
between the public internet and the DRF backend.

Usage flow:
  Angular -> POST /api/auth/login/sso (with authorization_code) -> BFF
  BFF -> Exchange code with SSO provider -> Get access_token + refresh_token
  BFF -> Store refresh_token in HTTP-only cookie
  BFF -> Return access_token in response body to Angular
  Angular -> Use access_token in Authorization: Bearer header for API calls
  BFF -> Refresh endpoint periodically refreshes tokens via cookies
"""

import requests
import json
import logging
from datetime import datetime, timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model
from django.utils.decorators import method_decorator
from django.views import View

from rest_framework import viewsets, status, serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

logger = logging.getLogger(__name__)
User = get_user_model()


class BFFLoginSerializer(serializers.Serializer):
    """Serializer for BFF login endpoint."""
    authorization_code = serializers.CharField()
    code_verifier = serializers.CharField()  # PKCE code_verifier
    redirect_uri = serializers.CharField()


class BFFTokenRefreshSerializer(serializers.Serializer):
    """Serializer for token refresh endpoint."""
    pass  # No body needed; refresh_token comes from cookies


class BFFLogoutSerializer(serializers.Serializer):
    """Serializer for logout endpoint."""
    pass  # No body needed


def exchange_authorization_code_for_tokens(authorization_code, code_verifier, redirect_uri):
    """
    Exchange OAuth2 authorization code for access_token and refresh_token.
    
    Args:
        authorization_code: The code returned from SSO provider
        code_verifier: PKCE code_verifier (from Angular)
        redirect_uri: Must match the registered redirect URI
        
    Returns:
        dict with access_token, refresh_token, expires_in, token_type
        
    Raises:
        requests.RequestException: If token exchange fails
    """
    token_url = settings.SSO_TOKEN_URL  # e.g., http://localhost:8000/o/token/
    
    payload = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'client_id': settings.BFF_CLIENT_ID,
        'client_secret': settings.BFF_CLIENT_SECRET,
        'redirect_uri': redirect_uri,
        'code_verifier': code_verifier,  # PKCE
    }
    
    try:
        response = requests.post(token_url, data=payload, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Token exchange failed: {e}")
        raise


def refresh_access_token(refresh_token):
    """
    Use refresh_token to get a new access_token.
    
    Args:
        refresh_token: The refresh token stored in cookies
        
    Returns:
        dict with access_token, refresh_token (new), expires_in, token_type
        
    Raises:
        requests.RequestException: If refresh fails
    """
    token_url = settings.SSO_TOKEN_URL
    
    payload = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': settings.BFF_CLIENT_ID,
        'client_secret': settings.BFF_CLIENT_SECRET,
    }
    
    try:
        response = requests.post(token_url, data=payload, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Token refresh failed: {e}")
        raise


def set_refresh_token_cookie(response, refresh_token, expires_in):
    """
    Set refresh_token in HTTP-only, Secure, SameSite cookie.
    
    Args:
        response: Django HttpResponse object
        refresh_token: The refresh token to store
        expires_in: Token lifetime in seconds
    """
    max_age = int(expires_in) if expires_in else (30 * 24 * 60 * 60)  # Default 30 days
    
    response.set_cookie(
        key='refresh_token',
        value=refresh_token,
        max_age=max_age,
        expires=datetime.utcnow() + timedelta(seconds=max_age),
        secure=settings.SECURE_COOKIE_SECURE,  # Set True in production (HTTPS only)
        httponly=True,  # Critical: not accessible to JavaScript
        samesite=settings.SECURE_COOKIE_SAMESITE,  # Strict or Lax
    )


def clear_refresh_token_cookie(response):
    """Clear refresh_token cookie."""
    response.delete_cookie('refresh_token', samesite=settings.SECURE_COOKIE_SAMESITE)


class BFFLoginView(View):
    """
    BFF Login endpoint: Exchange authorization code for tokens.
    
    POST /api/auth/login/sso
    Body: { authorization_code, code_verifier, redirect_uri }
    
    Returns: { access_token, expires_in, token_type } + refresh_token in cookie
    """
    
    @method_decorator(csrf_exempt)
    @method_decorator(require_http_methods(["POST"]))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def post(self, request):
        try:
            data = json.loads(request.body)
            authorization_code = data.get('authorization_code')
            code_verifier = data.get('code_verifier')
            redirect_uri = data.get('redirect_uri')
            
            if not all([authorization_code, code_verifier, redirect_uri]):
                return JsonResponse(
                    {'error': 'Missing authorization_code, code_verifier, or redirect_uri'},
                    status=400
                )
            
            # Exchange code for tokens
            token_data = exchange_authorization_code_for_tokens(
                authorization_code, code_verifier, redirect_uri
            )
            
            access_token = token_data.get('access_token')
            refresh_token = token_data.get('refresh_token')
            expires_in = token_data.get('expires_in', 3600)
            token_type = token_data.get('token_type', 'Bearer')
            
            # Prepare response with access_token in body
            response_data = {
                'access_token': access_token,
                'expires_in': expires_in,
                'token_type': token_type,
            }
            
            response = JsonResponse(response_data, status=200)
            
            # Store refresh_token in HTTP-only cookie
            if refresh_token:
                set_refresh_token_cookie(response, refresh_token, expires_in)
            
            return response
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except requests.RequestException as e:
            logger.error(f"BFF login failed: {e}")
            return JsonResponse(
                {'error': 'Failed to exchange authorization code'},
                status=400
            )
        except Exception as e:
            logger.error(f"Unexpected error in BFF login: {e}")
            return JsonResponse({'error': 'Internal server error'}, status=500)


class BFFTokenRefreshView(View):
    """
    BFF Token refresh endpoint: Use refresh_token from cookies to get new access_token.
    
    POST /api/auth/refresh/
    No body required; refresh_token comes from HTTP-only cookie.
    
    Returns: { access_token, expires_in, token_type } + potentially new refresh_token in cookie
    """
    
    @method_decorator(csrf_exempt)
    @method_decorator(require_http_methods(["POST"]))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def post(self, request):
        try:
            refresh_token = request.COOKIES.get('refresh_token')
            
            if not refresh_token:
                return JsonResponse(
                    {'error': 'No refresh_token in cookies. Please log in.'},
                    status=401
                )
            
            # Refresh the tokens
            token_data = refresh_access_token(refresh_token)
            
            access_token = token_data.get('access_token')
            new_refresh_token = token_data.get('refresh_token', refresh_token)
            expires_in = token_data.get('expires_in', 3600)
            token_type = token_data.get('token_type', 'Bearer')
            
            response_data = {
                'access_token': access_token,
                'expires_in': expires_in,
                'token_type': token_type,
            }
            
            response = JsonResponse(response_data, status=200)
            
            # Update refresh_token cookie if a new one was issued
            if new_refresh_token:
                set_refresh_token_cookie(response, new_refresh_token, expires_in)
            
            return response
            
        except requests.RequestException as e:
            logger.error(f"BFF refresh failed: {e}")
            return JsonResponse(
                {'error': 'Failed to refresh token'},
                status=400
            )
        except Exception as e:
            logger.error(f"Unexpected error in BFF refresh: {e}")
            return JsonResponse({'error': 'Internal server error'}, status=500)


class BFFLogoutView(View):
    """
    BFF Logout endpoint: Clear refresh_token and revoke tokens if possible.
    
    POST /api/auth/logout/
    No body required.
    
    Returns: { message: 'Logged out successfully' }
    """
    
    @method_decorator(csrf_exempt)
    @method_decorator(require_http_methods(["POST"]))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def post(self, request):
        try:
            refresh_token = request.COOKIES.get('refresh_token')
            
            # Optional: revoke token at provider if endpoint available
            if refresh_token and hasattr(settings, 'SSO_REVOKE_URL'):
                try:
                    revoke_url = settings.SSO_REVOKE_URL
                    requests.post(
                        revoke_url,
                        data={
                            'token': refresh_token,
                            'client_id': settings.BFF_CLIENT_ID,
                            'client_secret': settings.BFF_CLIENT_SECRET,
                        },
                        timeout=5
                    )
                except Exception as e:
                    logger.warning(f"Token revocation failed: {e}")
            
            response = JsonResponse(
                {'message': 'Logged out successfully'},
                status=200
            )
            
            # Clear refresh_token cookie
            clear_refresh_token_cookie(response)
            
            return response
            
        except Exception as e:
            logger.error(f"Unexpected error in BFF logout: {e}")
            return JsonResponse({'error': 'Internal server error'}, status=500)


# Optional: ViewSet-based alternative to the class-based views above
class BFFAuthViewSet(viewsets.ViewSet):
    """
    DRF ViewSet-based BFF endpoints (alternative to class-based views).
    
    Endpoints:
    - POST /api/auth/login/ - exchange authorization code
    - POST /api/auth/refresh/ - refresh access token
    - POST /api/auth/logout/ - logout and clear tokens
    """
    
    permission_classes = [AllowAny]
    
    @action(detail=False, methods=['post'], name='login')
    def login(self, request):
        """Exchange authorization code for access_token."""
        serializer = BFFLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            token_data = exchange_authorization_code_for_tokens(
                serializer.validated_data['authorization_code'],
                serializer.validated_data['code_verifier'],
                serializer.validated_data['redirect_uri'],
            )
            
            access_token = token_data.get('access_token')
            refresh_token = token_data.get('refresh_token')
            expires_in = token_data.get('expires_in', 3600)
            token_type = token_data.get('token_type', 'Bearer')
            
            response = Response(
                {
                    'access_token': access_token,
                    'expires_in': expires_in,
                    'token_type': token_type,
                },
                status=status.HTTP_200_OK
            )
            
            if refresh_token:
                set_refresh_token_cookie(response, refresh_token, expires_in)
            
            return response
            
        except requests.RequestException as e:
            logger.error(f"BFF login failed: {e}")
            return Response(
                {'error': 'Failed to exchange authorization code'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['post'], name='refresh')
    def refresh(self, request):
        """Refresh access_token using refresh_token from cookies."""
        try:
            refresh_token = request.COOKIES.get('refresh_token')
            
            if not refresh_token:
                return Response(
                    {'error': 'No refresh_token in cookies. Please log in.'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            token_data = refresh_access_token(refresh_token)
            
            access_token = token_data.get('access_token')
            new_refresh_token = token_data.get('refresh_token', refresh_token)
            expires_in = token_data.get('expires_in', 3600)
            token_type = token_data.get('token_type', 'Bearer')
            
            response = Response(
                {
                    'access_token': access_token,
                    'expires_in': expires_in,
                    'token_type': token_type,
                },
                status=status.HTTP_200_OK
            )
            
            if new_refresh_token:
                set_refresh_token_cookie(response, new_refresh_token, expires_in)
            
            return response
            
        except requests.RequestException as e:
            logger.error(f"BFF refresh failed: {e}")
            return Response(
                {'error': 'Failed to refresh token'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['post'], name='logout')
    def logout(self, request):
        """Logout and clear refresh_token."""
        try:
            refresh_token = request.COOKIES.get('refresh_token')
            
            if refresh_token and hasattr(settings, 'SSO_REVOKE_URL'):
                try:
                    requests.post(
                        settings.SSO_REVOKE_URL,
                        data={
                            'token': refresh_token,
                            'client_id': settings.BFF_CLIENT_ID,
                            'client_secret': settings.BFF_CLIENT_SECRET,
                        },
                        timeout=5
                    )
                except Exception as e:
                    logger.warning(f"Token revocation failed: {e}")
            
            response = Response(
                {'message': 'Logged out successfully'},
                status=status.HTTP_200_OK
            )
            
            clear_refresh_token_cookie(response)
            return response
            
        except Exception as e:
            logger.error(f"BFF logout failed: {e}")
            return Response(
                {'error': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
