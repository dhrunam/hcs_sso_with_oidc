# apps/social/views.py
"""
Views for social authentication and connection management.
"""

import logging
from typing import Dict, Any, Optional
from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth import login, get_user_model
from django.utils import timezone
from rest_framework import viewsets, generics, status
from rest_framework.response import Response
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.views import APIView
from rest_framework.exceptions import ValidationError, PermissionDenied
from social_django.utils import load_strategy, load_backend
from social_core.exceptions import (
    AuthAlreadyAssociated, AuthException, AuthForbidden,
    AuthCanceled, AuthMissingParameter, AuthStateMissing, 
    AuthStateForbidden, AuthTokenError, AuthUnknownError
)
from social_django.models import UserSocialAuth

from .models import SocialConnection, SocialLoginEvent
from .serializers import (
    SocialConnectionSerializer, SocialLoginEventSerializer,
    ConnectSocialSerializer, DisconnectSocialSerializer,
    RefreshSocialTokenSerializer, SyncSocialProfileSerializer,
    SetPrimaryConnectionSerializer, SocialProviderSerializer
)
from apps.core.models import UserProfile
from apps.social.serializers import get_available_providers

User = get_user_model()
logger = logging.getLogger(__name__)


class SocialAuthBaseView(APIView):
    """Base view class for social authentication with common utilities"""
    
    def _get_client_ip(self, request) -> str:
        """Extract client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Handle multiple proxies
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip
    
    def _create_auth_event(
        self, 
        request, 
        provider: str, 
        email: str = '', 
        success: bool = True, 
        error_message: str = '',
        event_type: str = 'login',
        extra_data: Dict[str, Any] = None
    ) -> SocialLoginEvent:
        """
        Create a SocialLoginEvent for audit logging
        
        Args:
            request: HTTP request object
            provider: Social provider name
            email: Email attempted
            success: Whether authentication succeeded
            error_message: Error message if failed
            event_type: Type of event (login, connect, disconnect, etc.)
            extra_data: Additional context data
            
        Returns:
            Created SocialLoginEvent instance
        """
        try:
            event = SocialLoginEvent.objects.create(
                user=request.user if request.user.is_authenticated else None,
                event_type=event_type,
                provider=provider,
                email_attempted=email,
                success=success,
                error_message=error_message[:500] if error_message else '',
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                referer=request.META.get('HTTP_REFERER', ''),
                extra_data=extra_data or {}
            )
            return event
        except Exception as e:
            logger.error(f"Failed to create SocialLoginEvent: {e}")
            return None
    
    def _validate_redirect_url(self, redirect_url: str) -> str:
        """
        Validate redirect URL to prevent open redirect vulnerabilities
        
        Args:
            redirect_url: URL to validate
            
        Returns:
            Safe redirect URL or default
        """
        # List of allowed redirect domains (configure in settings)
        allowed_domains = getattr(settings, 'ALLOWED_REDIRECT_DOMAINS', [])
        default_redirect = getattr(settings, 'LOGIN_REDIRECT_URL', '/')
        
        if not redirect_url:
            return default_redirect
        
        # Simple validation - in production, use a more robust solution
        from django.utils.http import url_has_allowed_host_and_scheme
        
        if url_has_allowed_host_and_scheme(
            redirect_url, 
            allowed_hosts=settings.ALLOWED_HOSTS
        ):
            return redirect_url
        
        return default_redirect


class SocialLoginInitiateView(SocialAuthBaseView):
    """
    Initiate social login OAuth flow
    
    GET /api/social/login/<provider>/?next=/dashboard/
    """
    permission_classes = [AllowAny]
    
    def get(self, request, provider: str):
        """
        Start OAuth2/OIDC flow with specified provider
        
        Args:
            provider: Social provider identifier (google-oauth2, facebook, etc.)
        """
        try:
            # Validate provider
            available_providers = get_available_providers(request)
            provider_ids = [p[0] for p in available_providers]
            
            if provider not in provider_ids:
                self._create_auth_event(
                    request, provider, '', False,
                    f'Provider {provider} not configured',
                    'login', {'action': 'initiate'}
                )
                raise ValidationError(f"Provider '{provider}' is not available")
            
            # Store state in session
            strategy = load_strategy(request)
            
            # Get redirect URL from query params or default
            next_url = request.GET.get('next', '')
            safe_next_url = self._validate_redirect_url(next_url)
            
            # Store in session for callback
            request.session['social_auth_next'] = safe_next_url
            request.session['social_auth_provider'] = provider
            request.session['social_auth_state'] = strategy.session_get('state')
            
            # Initialize backend
            backend = load_backend(strategy, provider, redirect_uri=None)
            
            # Get authorization URL
            redirect_uri = request.build_absolute_uri(f'/api/social/callback/{provider}/')
            auth_url = backend.auth_url(redirect_uri=redirect_uri)
            
            # Log initiation
            self._create_auth_event(
                request, provider, '', True,
                '', 'login', {'action': 'initiate', 'next_url': safe_next_url}
            )
            
            logger.info(f"Social login initiated for provider: {provider}")
            
            # Redirect to provider's authorization endpoint
            return redirect(auth_url)
            
        except (AuthMissingParameter, AuthStateMissing) as e:
            error_msg = f"Missing required parameters: {str(e)}"
            self._create_auth_event(
                request, provider, '', False, error_msg,
                'login', {'action': 'initiate', 'error_type': 'missing_params'}
            )
            return Response(
                {'error': 'Authentication configuration error'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        except Exception as e:
            error_msg = f"Failed to initiate login: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self._create_auth_event(
                request, provider, '', False, error_msg,
                'login', {'action': 'initiate', 'error_type': 'exception'}
            )
            return Response(
                {'error': 'Failed to initiate social login'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SocialCallbackView(SocialAuthBaseView):
    """
    Handle OAuth2/OIDC callback from social providers
    
    GET /api/social/callback/<provider>/
    """
    permission_classes = [AllowAny]
    
    def get(self, request, provider: str):
        """
        Process OAuth2 callback and authenticate user
        
        Args:
            provider: Social provider identifier
        """
        email = ''
        try:
            # Load strategy and backend
            strategy = load_strategy(request)
            redirect_uri = request.build_absolute_uri(f'/api/social/callback/{provider}/')
            backend = load_backend(strategy, provider, redirect_uri=redirect_uri)
            
            # Complete authentication
            user = backend.complete(user=request.user)
            
            if not user or not user.is_authenticated:
                error_msg = 'Authentication failed: No user returned'
                self._create_auth_event(
                    request, provider, '', False, error_msg,
                    'login', {'action': 'callback'}
                )
                raise AuthException(backend, error_msg)
            
            # Login the user
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            
            # Get email for logging
            email = user.email
            
            # Get associated UserSocialAuth
            try:
                social_auth = UserSocialAuth.objects.get(
                    user=user,
                    provider=provider
                )
                
                # SocialConnection should be created via signals, but ensure it exists
                SocialConnection.objects.get_or_create(
                    social_auth=social_auth,
                    defaults={
                        'user': user,
                        'provider': provider,
                        'provider_id': social_auth.uid,
                        'email': user.email,
                        'name': user.get_full_name() or '',
                        'is_active': True,
                        'last_used': timezone.now(),
                    }
                )
                
            except UserSocialAuth.DoesNotExist:
                logger.warning(f"UserSocialAuth not found for user {user.id} via {provider}")
            
            # Get redirect URL from session
            redirect_url = request.session.pop('social_auth_next', '')
            safe_redirect_url = self._validate_redirect_url(redirect_url)
            
            # Clear session data
            for key in ['social_auth_next', 'social_auth_provider', 'social_auth_state']:
                if key in request.session:
                    del request.session[key]
            
            # Create success event
            self._create_auth_event(
                request, provider, email, True, '',
                'login', {
                    'action': 'callback',
                    'user_id': user.id,
                    'is_new': not UserSocialAuth.objects.filter(user=user).exists()
                }
            )
            
            logger.info(f"Successful social login for {email} via {provider}")
            
            # Generate tokens for API access
            from rest_framework.authtoken.models import Token
            token, created = Token.objects.get_or_create(user=user)
            
            # Return JSON response instead of redirect for SPA
            # Frontend should handle the redirect
            return Response({
                'success': True,
                'message': 'Authentication successful',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_active': user.is_active,
                },
                'token': token.key,
                'redirect_url': safe_redirect_url,
                'provider': provider,
            })
            
        except AuthAlreadyAssociated as e:
            error_msg = 'This social account is already associated with another user'
            self._create_auth_event(
                request, provider, email, False, error_msg,
                'login', {'action': 'callback', 'error_type': 'already_associated'}
            )
            return Response(
                {'error': error_msg, 'code': 'ACCOUNT_ALREADY_ASSOCIATED'},
                status=status.HTTP_409_CONFLICT
            )
            
        except AuthForbidden as e:
            error_msg = 'Access denied by provider or domain restrictions'
            self._create_auth_event(
                request, provider, email, False, error_msg,
                'login', {'action': 'callback', 'error_type': 'forbidden'}
            )
            return Response(
                {'error': error_msg, 'code': 'ACCESS_DENIED'},
                status=status.HTTP_403_FORBIDDEN
            )
            
        except AuthCanceled as e:
            error_msg = 'Authentication was canceled by user'
            self._create_auth_event(
                request, provider, email, False, error_msg,
                'login', {'action': 'callback', 'error_type': 'canceled'}
            )
            return Response(
                {'error': error_msg, 'code': 'AUTH_CANCELED'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        except (AuthStateMissing, AuthStateForbidden) as e:
            error_msg = 'Invalid authentication state. Please try again.'
            self._create_auth_event(
                request, provider, email, False, error_msg,
                'login', {'action': 'callback', 'error_type': 'state_error'}
            )
            return Response(
                {'error': error_msg, 'code': 'INVALID_STATE'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        except AuthTokenError as e:
            error_msg = 'Token validation failed'
            self._create_auth_event(
                request, provider, email, False, error_msg,
                'login', {'action': 'callback', 'error_type': 'token_error'}
            )
            return Response(
                {'error': error_msg, 'code': 'TOKEN_ERROR'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        except AuthUnknownError as e:
            error_msg = 'Unknown authentication error'
            self._create_auth_event(
                request, provider, email, False, error_msg,
                'login', {'action': 'callback', 'error_type': 'unknown'}
            )
            return Response(
                {'error': error_msg, 'code': 'UNKNOWN_ERROR'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
        except Exception as e:
            error_msg = f'Authentication failed: {str(e)}'
            logger.error(error_msg, exc_info=True)
            self._create_auth_event(
                request, provider, email, False, error_msg,
                'login', {'action': 'callback', 'error_type': 'exception'}
            )
            return Response(
                {'error': 'Authentication failed. Please try again.', 'code': 'AUTH_FAILED'},
                status=status.HTTP_400_BAD_REQUEST
            )


class SocialConnectionsViewSet(viewsets.ViewSet):
    """
    ViewSet for managing user's social connections
    
    GET /api/social/connections/ - List connections
    POST /api/social/connections/connect/ - Connect new account
    POST /api/social/connections/disconnect/google-oauth2/ - Disconnect account
    POST /api/social/connections/refresh/google-oauth2/ - Refresh token
    POST /api/social/connections/sync/google-oauth2/ - Sync profile
    POST /api/social/connections/primary/google-oauth2/ - Set as primary
    """
    permission_classes = [IsAuthenticated]
    
    def list(self, request):
        """Get user's active social connections"""
        connections = SocialConnection.objects.filter(
            user=request.user, 
            is_active=True
        ).select_related('social_auth').order_by('-is_primary', '-last_used')
        
        serializer = SocialConnectionSerializer(
            connections, 
            many=True,
            context={'request': request}
        )
        
        return Response({
            'connections': serializer.data,
            'count': connections.count(),
            'has_password': request.user.has_usable_password(),
        })
    
    @action(detail=False, methods=['post'])
    def connect(self, request):
        """
        Connect a new social account using direct token
        
        This is useful for mobile apps or when you have tokens from another source
        """
        serializer = ConnectSocialSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        data = serializer.validated_data
        provider = data['provider']
        
        try:
            # In production, you would validate the token with the provider
            # This is a simplified example - implement proper validation
            
            # Create UserSocialAuth entry
            social_auth, created = UserSocialAuth.objects.get_or_create(
                user=request.user,
                provider=provider,
                uid=f"manual_{provider}_{request.user.id}",
                defaults={
                    'extra_data': {
                        'access_token': data['access_token'],
                        'refresh_token': data.get('refresh_token'),
                        'expires_in': data.get('expires_in'),
                        'id_token': data.get('id_token'),
                        'scopes': data.get('scopes'),
                    }
                }
            )
            
            if not created:
                # Update existing
                social_auth.extra_data.update({
                    'access_token': data['access_token'],
                    'refresh_token': data.get('refresh_token'),
                    'expires_in': data.get('expires_in'),
                })
                social_auth.save()
            
            # SocialConnection should be created via signals
            connection = SocialConnection.objects.filter(
                user=request.user,
                provider=provider,
                is_active=True
            ).first()
            
            if connection:
                # Update connection with token info
                connection.update_token(
                    access_token=data['access_token'],
                    refresh_token=data.get('refresh_token'),
                    expires_in=data.get('expires_in'),
                    scopes=data.get('scopes'),
                )
            
            # Create audit event
            SocialLoginEvent.objects.create(
                user=request.user,
                event_type='connect',
                provider=provider,
                email_attempted=request.user.email,
                success=True,
                ip_address=request.META.get('REMOTE_ADDR', ''),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                extra_data={'method': 'direct_token', 'scopes': data.get('scopes')}
            )
            
            logger.info(f"User {request.user.email} connected {provider} via direct token")
            
            return Response({
                'success': True,
                'message': f'Successfully connected {provider} account',
                'connection': SocialConnectionSerializer(connection).data if connection else None
            })
            
        except Exception as e:
            logger.error(f"Failed to connect social account via direct token: {e}", exc_info=True)
            
            SocialLoginEvent.objects.create(
                user=request.user,
                event_type='connect',
                provider=provider,
                email_attempted=request.user.email,
                success=False,
                error_message=str(e)[:200],
                ip_address=request.META.get('REMOTE_ADDR', ''),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                extra_data={'method': 'direct_token', 'error': str(e)}
            )
            
            return Response(
                {'error': f'Failed to connect {provider} account: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['post'], url_path='disconnect/(?P<provider>[^/.]+)')
    def disconnect(self, request, provider=None):
        """Disconnect a social account"""
        serializer = DisconnectSocialSerializer(
            data={'provider': provider},
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        data = serializer.validated_data
        connection = data['connection']
        
        try:
            # Deactivate our SocialConnection
            connection.is_active = False
            connection.save()
            
            # Delete UserSocialAuth if it exists
            UserSocialAuth.objects.filter(
                user=request.user,
                provider=provider
            ).delete()
            
            # Handle primary connection reassignment
            if connection.is_primary:
                if 'new_primary' in data:
                    new_primary = data['new_primary']
                    new_primary.is_primary = True
                    new_primary.save()
                    logger.info(f"Set {new_primary.provider} as new primary for user {request.user.id}")
                elif 'use_password_login' in data:
                    logger.info(f"User {request.user.id} will use password login after disconnecting primary")
            
            # Update UserProfile if needed
            profile = UserProfile.objects.filter(user=request.user).first()
            if profile and profile.identity_provider == provider:
                # Find another active connection
                other_connection = SocialConnection.objects.filter(
                    user=request.user,
                    is_active=True
                ).first()
                
                if other_connection:
                    profile.identity_provider = other_connection.provider
                else:
                    profile.identity_provider = 'local'
                
                profile.save()
            
            # Create audit event
            SocialLoginEvent.objects.create(
                user=request.user,
                event_type='disconnect',
                provider=provider,
                email_attempted=request.user.email,
                success=True,
                ip_address=request.META.get('REMOTE_ADDR', ''),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                extra_data={
                    'was_primary': connection.is_primary,
                    'connection_id': connection.id
                }
            )
            
            logger.info(f"User {request.user.email} disconnected {provider}")
            
            return Response({
                'success': True,
                'message': f'Successfully disconnected {provider} account',
                'was_primary': connection.is_primary,
            })
            
        except Exception as e:
            logger.error(f"Failed to disconnect social account: {e}", exc_info=True)
            
            SocialLoginEvent.objects.create(
                user=request.user,
                event_type='disconnect',
                provider=provider,
                email_attempted=request.user.email,
                success=False,
                error_message=str(e)[:200],
                ip_address=request.META.get('REMOTE_ADDR', ''),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                extra_data={'error': str(e)}
            )
            
            return Response(
                {'error': f'Failed to disconnect {provider} account: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['post'], url_path='refresh/(?P<provider>[^/.]+)')
    def refresh_token(self, request, provider=None):
        """Refresh OAuth token for a social connection"""
        serializer = RefreshSocialTokenSerializer(
            data={'provider': provider},
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        data = serializer.validated_data
        connection = data['connection']
        
        try:
            # In production, implement actual token refresh
            # This is a placeholder - use the provider's token refresh endpoint
            
            # For now, just update the last used timestamp
            connection.last_used = timezone.now()
            connection.save()
            
            logger.info(f"Token refresh requested for {provider} by user {request.user.email}")
            
            return Response({
                'success': True,
                'message': f'Token refresh functionality needs to be implemented for {provider}',
                'connection': SocialConnectionSerializer(connection).data,
            })
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}", exc_info=True)
            return Response(
                {'error': f'Token refresh failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['post'], url_path='sync/(?P<provider>[^/.]+)')
    def sync_profile(self, request, provider=None):
        """Sync profile data from social provider"""
        serializer = SyncSocialProfileSerializer(
            data={'provider': provider},
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        data = serializer.validated_data
        connection = data['connection']
        
        try:
            # In production, fetch fresh data from provider API
            # This is a placeholder
            
            connection.last_synced = timezone.now()
            connection.save()
            
            logger.info(f"Profile sync requested for {provider} by user {request.user.email}")
            
            return Response({
                'success': True,
                'message': f'Profile sync functionality needs to be implemented for {provider}',
                'last_synced': connection.last_synced,
            })
            
        except Exception as e:
            logger.error(f"Profile sync failed: {e}", exc_info=True)
            return Response(
                {'error': f'Profile sync failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['post'], url_path='primary/(?P<provider>[^/.]+)')
    def set_primary(self, request, provider=None):
        """Set a social connection as primary login method"""
        serializer = SetPrimaryConnectionSerializer(
            data={'provider': provider},
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        data = serializer.validated_data
        connection = data['connection']
        
        try:
            # Set as primary
            connection.is_primary = True
            connection.save()
            
            # Update UserProfile
            profile = UserProfile.objects.filter(user=request.user).first()
            if profile:
                profile.identity_provider = connection.provider
                profile.save()
            
            # Create audit event
            SocialLoginEvent.objects.create(
                user=request.user,
                event_type='connect',  # Reusing connect type
                provider=provider,
                email_attempted=request.user.email,
                success=True,
                extra_data={'action': 'set_primary', 'connection_id': connection.id}
            )
            
            logger.info(f"User {request.user.email} set {provider} as primary connection")
            
            return Response({
                'success': True,
                'message': f'{provider} set as primary login method',
                'connection': SocialConnectionSerializer(connection).data,
            })
            
        except Exception as e:
            logger.error(f"Failed to set primary connection: {e}", exc_info=True)
            return Response(
                {'error': f'Failed to set primary connection: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )


class SocialProvidersView(SocialAuthBaseView):
    """
    List available social providers with configuration
    
    GET /api/social/providers/
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Get list of configured social providers"""
        try:
            available_providers = get_available_providers(request)
            
            # Serialize provider information
            serializer = SocialProviderSerializer(
                available_providers, 
                many=True,
                context={'request': request}
            )
            
            return Response({
                'providers': serializer.data,
                'count': len(available_providers),
                'social_login_enabled': len(available_providers) > 0,
            })
            
        except Exception as e:
            logger.error(f"Failed to get social providers: {e}", exc_info=True)
            return Response(
                {'error': 'Failed to retrieve social providers'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SocialLoginHistoryView(generics.ListAPIView):
    """
    Get user's social login history
    
    GET /api/social/history/
    """
    permission_classes = [IsAuthenticated]
    serializer_class = SocialLoginEventSerializer
    
    def get_queryset(self):
        """Return user's social login events"""
        return SocialLoginEvent.objects.filter(
            user=self.request.user
        ).select_related('user').order_by('-created_at')
    
    def list(self, request, *args, **kwargs):
        """Override to add metadata"""
        queryset = self.filter_queryset(self.get_queryset())
        
        # Pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        
        # Add summary statistics
        total = queryset.count()
        successful = queryset.filter(success=True).count()
        failed = total - successful
        
        # Recent activity
        recent_cutoff = timezone.now() - timezone.timedelta(days=7)
        recent_activity = queryset.filter(created_at__gte=recent_cutoff).count()
        
        return Response({
            'events': serializer.data,
            'summary': {
                'total': total,
                'successful': successful,
                'failed': failed,
                'recent_activity': recent_activity,
            }
        })


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_social_stats(request):
    """
    Admin endpoint for social authentication statistics
    
    GET /api/social/admin/stats/
    """
    try:
        # Total social connections
        total_connections = SocialConnection.objects.filter(is_active=True).count()
        
        # Connections by provider
        connections_by_provider = list(
            SocialConnection.objects.filter(is_active=True)
            .values('provider')
            .annotate(count=models.Count('id'))
            .order_by('-count')
        )
        
        # Recent signups (last 30 days)
        thirty_days_ago = timezone.now() - timezone.timedelta(days=30)
        recent_signups = SocialConnection.objects.filter(
            is_active=True,
            connected_at__gte=thirty_days_ago
        ).count()
        
        # Login events in last 24 hours
        twentyfour_hours_ago = timezone.now() - timezone.timedelta(hours=24)
        recent_logins = SocialLoginEvent.objects.filter(
            created_at__gte=twentyfour_hours_ago,
            event_type='login'
        ).count()
        
        # Failed login attempts in last 24 hours
        failed_logins = SocialLoginEvent.objects.filter(
            created_at__gte=twentyfour_hours_ago,
            event_type='login',
            success=False
        ).count()
        
        return Response({
            'total_connections': total_connections,
            'connections_by_provider': connections_by_provider,
            'recent_signups': recent_signups,
            'recent_logins': recent_logins,
            'failed_logins': failed_logins,
            'top_providers': connections_by_provider[:5],
        })
        
    except Exception as e:
        logger.error(f"Failed to get admin stats: {e}", exc_info=True)
        return Response(
            {'error': 'Failed to retrieve statistics'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )