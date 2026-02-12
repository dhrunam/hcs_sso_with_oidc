# apps/users/views.py
"""
User management API endpoints.
Handles user registration, profile management, authentication, and admin operations.
"""

import logging
from typing import Dict, Any, Optional
from django.conf import settings
from django.contrib.auth import logout, get_user_model
from django.shortcuts import get_object_or_404
from django.db.models import Q
from django.utils import timezone
from rest_framework import viewsets, generics, status, permissions, filters
from rest_framework.response import Response
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound
from rest_framework.pagination import PageNumberPagination
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken

from .serializers import (
    UserSerializer, UserCreateSerializer, UserUpdateSerializer,
    AdminUserUpdateSerializer, PasswordChangeSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
    UserProfileSerializer, UserMinimalSerializer,
    UserBulkUpdateSerializer, UserStatsSerializer, get_user_stats,
    DepartmentSerializer, OrganizationSerializer
)
from apps.core.models import UserProfile, Department, Organization
from apps.social.models import SocialConnection, SocialLoginEvent
from apps.social.serializers import SocialConnectionSerializer
from apps.social.views import get_available_providers

logger = logging.getLogger(__name__)
User = get_user_model()


class StandardResultsSetPagination(PageNumberPagination):
    """Standard pagination for user lists"""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


class UserRegistrationView(generics.CreateAPIView):
    """
    User registration endpoint
    
    POST /api/users/register/
    """
    permission_classes = [AllowAny]
    serializer_class = UserCreateSerializer
    
    def create(self, request, *args, **kwargs):
        """Override to customize response"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            user = serializer.save()
            
            logger.info(f"New user registered: {user.username} ({user.email})")
            
            # Return user data (user should now authenticate using OAuth2)
            user_data = UserSerializer(user, context={'request': request}).data
            
            return Response({
                'user': user_data,
                'message': 'User registered successfully. Please authenticate using /o/token/ endpoint.',
                'requires_verification': getattr(settings, 'REQUIRE_EMAIL_VERIFICATION', False)
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"User registration failed: {e}", exc_info=True)
            return Response(
                {'error': 'Registration failed. Please try again.'},
                status=status.HTTP_400_BAD_REQUEST
            )


class UserProfileView(generics.RetrieveUpdateAPIView):
    """
    Get and update current user profile
    
    GET /api/users/profile/ - Get profile
    PUT /api/users/profile/ - Update profile
    """
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    
    def get_object(self):
        """Return the current user"""
        return self.request.user
    
    def get_serializer_class(self):
        """Use appropriate serializer for update vs retrieve"""
        if self.request.method in ['PUT', 'PATCH']:
            return UserUpdateSerializer
        return UserSerializer
    
    def retrieve(self, request, *args, **kwargs):
        """Override to include additional data"""
        user = self.get_object()
        serializer = self.get_serializer(user)
        
        # Add social connections
        connections = SocialConnection.objects.filter(
            user=user, is_active=True
        )
        connection_serializer = SocialConnectionSerializer(
            connections, many=True, context={'request': request}
        )
        
        response_data = serializer.data
        response_data['social_connections'] = connection_serializer.data
        
        return Response(response_data)
    
    def update(self, request, *args, **kwargs):
        """Override to add success message"""
        response = super().update(request, *args, **kwargs)
        response.data['message'] = 'Profile updated successfully'
        return response


class PasswordChangeView(generics.UpdateAPIView):
    """
    Change user password
    
    POST /api/users/password/change/
    """
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordChangeSerializer
    
    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            user = serializer.save()
            
            # Create audit event
            SocialLoginEvent.objects.create(
                user=user,
                event_type='connect',
                provider='local',
                email_attempted=user.email,
                success=True,
                ip_address=request.META.get('REMOTE_ADDR', ''),
                extra_data={'action': 'password_changed'}
            )
            
            logger.info(f"Password changed for user: {user.username}")
            
            return Response({
                'message': 'Password changed successfully',
                'requires_reauthentication': True
            })
            
        except Exception as e:
            logger.error(f"Password change failed for user {request.user.id}: {e}")
            return Response(
                {'error': 'Failed to change password'},
                status=status.HTTP_400_BAD_REQUEST
            )


class PasswordResetRequestView(generics.GenericAPIView):
    """
    Request password reset
    
    POST /api/users/password/reset/request/
    """
    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email__iexact=email, is_active=True)
            
            # Generate reset token (simplified - use Django's password reset in production)
            token = Token.objects.get_or_create(user=user)[0]
            
            # In production, send email with reset link
            # For now, just return token (not for production!)
            reset_url = f"{settings.FRONTEND_URL}/reset-password/{token.key}/"
            
            logger.info(f"Password reset requested for: {email}")
            
            return Response({
                'message': 'If an account exists with this email, you will receive a reset link.',
                'reset_url': reset_url if settings.DEBUG else None  # Only in debug
            })
            
        except User.DoesNotExist:
            # Don't reveal if user exists (security)
            return Response({
                'message': 'If an account exists with this email, you will receive a reset link.'
            })
        except Exception as e:
            logger.error(f"Password reset request failed for {email}: {e}")
            return Response(
                {'error': 'Password reset request failed'},
                status=status.HTTP_400_BAD_REQUEST
            )


class PasswordResetConfirmView(generics.GenericAPIView):
    """
    Confirm password reset
    
    POST /api/users/password/reset/confirm/
    """
    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # In production, validate token and uid properly
        # This is a simplified implementation
        
        try:
            # Get user from token
            token = serializer.validated_data['token']
            user_token = Token.objects.get(key=token)
            user = user_token.user
            
            # Set new password
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            # Delete token after use
            user_token.delete()
            
            # Create audit event
            SocialLoginEvent.objects.create(
                user=user,
                event_type='connect',
                provider='local',
                email_attempted=user.email,
                success=True,
                ip_address=request.META.get('REMOTE_ADDR', ''),
                extra_data={'action': 'password_reset'}
            )
            
            logger.info(f"Password reset completed for: {user.email}")
            
            return Response({
                'message': 'Password reset successful. You can now login with your new password.'
            })
            
        except Token.DoesNotExist:
            return Response(
                {'error': 'Invalid or expired reset token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Password reset confirm failed: {e}")
            return Response(
                {'error': 'Password reset failed'},
                status=status.HTTP_400_BAD_REQUEST
            )


class UserLogoutView(APIView):
    """
    Logout user and invalidate token
    
    POST /api/users/logout/
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            user = request.user
            
            # Invalidate token if using token auth
            if hasattr(request, 'auth') and isinstance(request.auth, Token):
                request.auth.delete()
                logger.info(f"Token invalidated for user: {user.username}")
            
            # Logout from Django session
            logout(request)
            
            # Create audit event
            SocialLoginEvent.objects.create(
                user=user,
                event_type='disconnect',
                provider='local',
                email_attempted=user.email,
                success=True,
                ip_address=request.META.get('REMOTE_ADDR', ''),
                extra_data={'action': 'logout'}
            )
            
            logger.info(f"User logged out: {user.username}")
            
            return Response({
                'message': 'Logged out successfully',
                'logout_time': timezone.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Logout failed for user {request.user.id}: {e}")
            return Response(
                {'error': 'Logout failed'},
                status=status.HTTP_400_BAD_REQUEST
            )


class LoginOptionsView(APIView):
    """
    Get available login options
    
    GET /api/users/login-options/
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        try:
            options = {
                'local_login_enabled': True,
                'social_login_enabled': False,
                'oidc_login_enabled': False,
                'saml_login_enabled': False,
                'options': []
            }
            
            # Local login option
            options['options'].append({
                'id': 'local',
                'name': 'Email & Password',
                'type': 'local',
                'auth_url': request.build_absolute_uri('/api/users/login/'),
                'icon': 'account_circle',
                'description': 'Login with your organization email and password',
                'enabled': True
            })
            
            # Get configured social providers
            social_providers = get_available_providers(request)
            if social_providers:
                options['social_login_enabled'] = True
                
                for provider_id, display_name in social_providers:
                    options['options'].append({
                        'id': provider_id,
                        'name': display_name,
                        'type': 'social',
                        'auth_url': request.build_absolute_uri(f'/api/social/login/{provider_id}/'),
                        'icon': provider_id.replace('-', '_'),
                        'description': f'Login with your {display_name} account',
                        'enabled': True
                    })
            
            # OIDC configuration if available
            if hasattr(settings, 'OIDC_RP_CLIENT_ID') and settings.OIDC_RP_CLIENT_ID:
                options['oidc_login_enabled'] = True
                options['options'].append({
                    'id': 'oidc',
                    'name': 'Organization SSO',
                    'type': 'oidc',
                    'auth_url': request.build_absolute_uri('/oidc/authenticate/'),
                    'icon': 'security',
                    'description': 'Single Sign-On with your organization',
                    'enabled': True
                })
            
            # Add OIDC discovery URL if OIDC is enabled
            if options['oidc_login_enabled']:
                options['oidc_discovery_url'] = request.build_absolute_uri('/.well-known/openid-configuration')
            
            # Add SAML if configured
            if hasattr(settings, 'SAML_CONFIG'):
                options['saml_login_enabled'] = True
                options['options'].append({
                    'id': 'saml',
                    'name': 'Enterprise SSO (SAML)',
                    'type': 'saml',
                    'auth_url': request.build_absolute_uri('/saml2/login/'),
                    'icon': 'corporate_fare',
                    'description': 'Enterprise Single Sign-On',
                    'enabled': True
                })
            
            return Response(options)
            
        except Exception as e:
            logger.error(f"Failed to get login options: {e}", exc_info=True)
            return Response(
                {'error': 'Failed to retrieve login options'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ==================== ADMIN VIEWS ====================

class AdminUserViewSet(viewsets.ModelViewSet):
    """
    Admin user management
    
    GET /api/admin/users/ - List users
    POST /api/admin/users/ - Create user
    GET /api/admin/users/{id}/ - Get user details
    PUT /api/admin/users/{id}/ - Update user
    DELETE /api/admin/users/{id}/ - Delete user
    """
    permission_classes = [IsAdminUser]
    queryset = User.objects.all().select_related('profile')
    pagination_class = StandardResultsSetPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['username', 'email', 'first_name', 'last_name', 'profile__employee_id']
    ordering_fields = ['id', 'username', 'email', 'date_joined', 'last_login']
    ordering = ['-date_joined']
    
    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return AdminUserUpdateSerializer
        elif self.action == 'list':
            return UserMinimalSerializer
        return UserSerializer
    
    def get_queryset(self):
        """Filter users based on query parameters"""
        queryset = super().get_queryset()
        
        # Filter by is_active
        is_active = self.request.query_params.get('is_active')
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        # Filter by identity provider
        identity_provider = self.request.query_params.get('identity_provider')
        if identity_provider:
            queryset = queryset.filter(profile__identity_provider=identity_provider)
        
        # Filter by department
        department_id = self.request.query_params.get('department_id')
        if department_id:
            queryset = queryset.filter(profile__department_id=department_id)
        
        # Filter by organization
        organization_id = self.request.query_params.get('organization_id')
        if organization_id:
            queryset = queryset.filter(profile__department__organization_id=organization_id)
        
        # Filter by staff/superuser status
        is_staff = self.request.query_params.get('is_staff')
        if is_staff is not None:
            queryset = queryset.filter(is_staff=is_staff.lower() == 'true')
        
        is_superuser = self.request.query_params.get('is_superuser')
        if is_superuser is not None:
            queryset = queryset.filter(is_superuser=is_superuser.lower() == 'true')
        
        return queryset
    
    def perform_destroy(self, instance):
        """Override to add audit logging"""
        logger.info(f"Admin deleted user: {instance.username} ({instance.email})")
        
        # Create audit event
        SocialLoginEvent.objects.create(
            user=None,
            event_type='disconnect',
            provider='system',
            email_attempted=instance.email,
            success=True,
            ip_address=self.request.META.get('REMOTE_ADDR', ''),
            extra_data={
                'action': 'admin_user_deleted',
                'deleted_by': self.request.user.username,
                'user_id': instance.id,
                'username': instance.username
            }
        )
        
        instance.delete()
    
    @action(detail=False, methods=['post'])
    def bulk_update(self, request):
        """Bulk update users"""
        serializer = UserBulkUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        data = serializer.validated_data
        user_ids = data['user_ids']
        
        try:
            users = User.objects.filter(id__in=user_ids)
            updated_count = 0
            
            if 'is_active' in data:
                users.update(is_active=data['is_active'])
                updated_count += users.count()
            
            if 'department_id' in data:
                department = Department.objects.get(id=data['department_id'])
                for user in users:
                    profile = user.profile
                    profile.department = department
                    profile.save()
                updated_count += users.count()
            
            logger.info(f"Admin bulk updated {updated_count} users")
            
            return Response({
                'message': f'Successfully updated {updated_count} users',
                'updated_count': updated_count
            })
            
        except Exception as e:
            logger.error(f"Bulk user update failed: {e}", exc_info=True)
            return Response(
                {'error': 'Bulk update failed'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=True, methods=['post'])
    def reset_password(self, request, pk=None):
        """Admin reset user password"""
        user = self.get_object()
        
        # Generate random password
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits
        new_password = ''.join(secrets.choice(alphabet) for _ in range(12))
        
        # Set new password
        user.set_password(new_password)
        user.save()
        
        # Create audit event
        SocialLoginEvent.objects.create(
            user=user,
            event_type='connect',
            provider='system',
            email_attempted=user.email,
            success=True,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            extra_data={
                'action': 'admin_password_reset',
                'reset_by': request.user.username
            }
        )
        
        logger.info(f"Admin reset password for user: {user.username}")
        
        return Response({
            'message': 'Password reset successfully',
            'new_password': new_password if settings.DEBUG else '********',  # Only show in debug
            'username': user.username,
            'email': user.email
        })
    
    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """Activate/deactivate user"""
        user = self.get_object()
        activate = request.data.get('activate', True)
        
        user.is_active = bool(activate)
        user.save()
        
        action = "activated" if user.is_active else "deactivated"
        logger.info(f"Admin {action} user: {user.username}")
        
        return Response({
            'message': f'User {action} successfully',
            'is_active': user.is_active
        })


class AdminUserStatsView(APIView):
    """
    Admin user statistics
    
    GET /api/admin/users/stats/
    """
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        try:
            stats = get_user_stats()
            serializer = UserStatsSerializer(stats)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Failed to get user stats: {e}", exc_info=True)
            return Response(
                {'error': 'Failed to retrieve user statistics'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminUserSearchView(generics.ListAPIView):
    """
    Search users for admin autocomplete
    
    GET /api/admin/users/search/?q=search_term
    """
    permission_classes = [IsAdminUser]
    serializer_class = UserMinimalSerializer
    pagination_class = None
    
    def get_queryset(self):
        query = self.request.query_params.get('q', '')
        if not query or len(query) < 2:
            return User.objects.none()
        
        return User.objects.filter(
            Q(username__icontains=query) |
            Q(email__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query) |
            Q(profile__employee_id__icontains=query)
        ).select_related('profile')[:10]


# ==================== PUBLIC VIEWS ====================

class PublicUserInfoView(APIView):
    """
    Get public user information (for mentions, etc.)
    
    GET /api/users/{id}/public/
    """
    permission_classes = [AllowAny]
    
    def get(self, request, user_id):
        try:
            user = get_object_or_404(User, id=user_id, is_active=True)
            
            return Response({
                'id': user.id,
                'username': user.username,
                'full_name': user.get_full_name() or user.username,
                'avatar': request.build_absolute_uri(user.profile.avatar.url) if user.profile.avatar else None,
                'job_title': user.profile.job_title if hasattr(user, 'profile') else '',
                'department': user.profile.department.name if hasattr(user, 'profile') and user.profile.department else '',
            })
        except Exception as e:
            logger.error(f"Failed to get public user info for {user_id}: {e}")
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class VerifyEmailView(APIView):
    """
    Verify email address
    
    POST /api/users/verify-email/
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            user = request.user
            token = request.data.get('token')
            
            if not token:
                return Response(
                    {'error': 'Verification token required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Verify token (simplified)
            profile = user.profile
            stored_token = profile.extra_data.get('email_verification_token', '') if profile.extra_data else ''
            
            if stored_token and token == stored_token:
                profile.email_verified = True
                profile.extra_data.pop('email_verification_token', None)
                profile.extra_data.pop('email_verification_sent', None)
                profile.save()
                
                logger.info(f"Email verified for user: {user.email}")
                
                return Response({
                    'message': 'Email verified successfully',
                    'email_verified': True
                })
            else:
                return Response(
                    {'error': 'Invalid verification token'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
        except Exception as e:
            logger.error(f"Email verification failed for user {request.user.id}: {e}")
            return Response(
                {'error': 'Email verification failed'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['post'])
    def resend_verification(self, request):
        """Resend verification email"""
        user = request.user
        
        # Call signal helper to send verification email
        from apps.users.signals import send_email_verification
        send_email_verification(user)
        
        return Response({
            'message': 'Verification email sent',
            'email': user.email
        })


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Health check endpoint
    
    GET /api/health/
    """
    try:
        # Check database connectivity
        User.objects.exists()
        
        # Check cache if configured
        from django.core.cache import cache
        cache.set('health_check', 'ok', 5)
        cache_result = cache.get('health_check') == 'ok'
        
        return Response({
            'status': 'healthy',
            'timestamp': timezone.now().isoformat(),
            'database': 'connected',
            'cache': 'connected' if cache_result else 'disconnected',
            'version': getattr(settings, 'APP_VERSION', '1.0.0'),
            'environment': settings.DEBUG and 'development' or 'production'
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return Response(
            {'status': 'unhealthy', 'error': str(e)},
            status=status.HTTP_503_SERVICE_UNAVAILABLE
        )