# apps/api/views.py
"""
API endpoints for system information, configuration, and integration.
This serves as the public API gateway for the SSO system.
"""

import logging
import platform
import socket
import sys
from typing import Dict, Any, Optional
from datetime import datetime
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache
from django.db import connection, DatabaseError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework import status
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.decorators import (
    api_view, permission_classes, throttle_classes
)
from rest_framework.versioning import URLPathVersioning

from apps.core.models import UserProfile, Department, Organization
from django.contrib.auth.models import User
from apps.social.models import SocialConnection, SocialLoginEvent
from oauth2_provider.models import Application
from apps.oidc.serializers import ClientRegistrationSerializer

logger = logging.getLogger(__name__)


class HealthCheckView(APIView):
    """
    Comprehensive health check endpoint
    
    GET /api/health/
    """
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]
    
    def get(self, request):
        """Check system health and return detailed status"""
        try:
            health_status = {
                'status': 'healthy',
                'timestamp': timezone.now().isoformat(),
                'service': 'organization-sso',
                'version': getattr(settings, 'APP_VERSION', '1.0.0'),
                'environment': settings.DEBUG and 'development' or 'production',
            }
            
            # Database health
            db_status = self._check_database()
            health_status.update(db_status)
            
            # Cache health
            cache_status = self._check_cache()
            health_status.update(cache_status)
            
            # Storage health (if using file storage)
            storage_status = self._check_storage()
            health_status.update(storage_status)
            
            # Authentication features status
            auth_features = self._check_auth_features()
            health_status.update(auth_features)
            
            # System info
            system_info = self._get_system_info()
            health_status.update(system_info)
            
            # Overall status
            overall_healthy = (
                db_status['database']['status'] == 'healthy' and
                cache_status['cache']['status'] == 'healthy' and
                storage_status['storage']['status'] in ['healthy', 'not_configured']
            )
            
            if not overall_healthy:
                health_status['status'] = 'degraded'
                health_status['overall_status'] = 'degraded'
            
            return Response(health_status)
            
        except Exception as e:
            logger.error(f"Health check failed: {e}", exc_info=True)
            return Response(
                {
                    'status': 'unhealthy',
                    'timestamp': timezone.now().isoformat(),
                    'error': str(e),
                    'service': 'organization-sso'
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
    
    def _check_database(self) -> Dict[str, Any]:
        """Check database connectivity and performance"""
        try:
            # Test connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            
            # Test basic queries
            User.objects.exists()
            
            # Get connection info
            db_info = {
                'engine': connection.vendor,
                'name': connection.settings_dict.get('NAME', 'unknown'),
                'host': connection.settings_dict.get('HOST', 'unknown'),
                'port': connection.settings_dict.get('PORT', 'unknown'),
            }
            
            # Get some stats
            total_users = User.objects.count()
            active_users = User.objects.filter(is_active=True).count()
            
            return {
                'database': {
                    'status': 'healthy',
                    'connection': db_info,
                    'stats': {
                        'total_users': total_users,
                        'active_users': active_users,
                    }
                }
            }
            
        except DatabaseError as e:
            logger.error(f"Database health check failed: {e}")
            return {
                'database': {
                    'status': 'unhealthy',
                    'error': str(e),
                }
            }
        except Exception as e:
            logger.error(f"Database health check error: {e}")
            return {
                'database': {
                    'status': 'unknown',
                    'error': str(e),
                }
            }
    
    def _check_cache(self) -> Dict[str, Any]:
        """Check cache connectivity"""
        try:
            # Test cache
            test_key = 'health_check_cache_test'
            test_value = timezone.now().isoformat()
            
            cache.set(test_key, test_value, 30)
            retrieved = cache.get(test_key)
            
            if retrieved == test_value:
                cache_status = 'healthy'
            else:
                cache_status = 'degraded'
            
            cache_info = {
                'backend': settings.CACHES['default']['BACKEND'].split('.')[-1],
                'status': cache_status,
                'test_passed': retrieved == test_value,
            }
            
            return {'cache': cache_info}
            
        except Exception as e:
            logger.error(f"Cache health check failed: {e}")
            return {
                'cache': {
                    'status': 'unhealthy',
                    'error': str(e),
                }
            }
    
    def _check_storage(self) -> Dict[str, Any]:
        """Check file storage (if configured)"""
        try:
            storage_backend = getattr(settings, 'DEFAULT_FILE_STORAGE', '')
            
            if not storage_backend or 'FileSystemStorage' in storage_backend:
                # Local file storage - check write permissions
                import os
                import tempfile
                
                test_dir = settings.MEDIA_ROOT if hasattr(settings, 'MEDIA_ROOT') else tempfile.gettempdir()
                test_file = os.path.join(test_dir, 'health_check_test.txt')
                
                try:
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    
                    storage_status = 'healthy'
                except (IOError, OSError) as e:
                    storage_status = 'unhealthy'
                    storage_error = str(e)
            else:
                # Cloud storage or other - just report configured
                storage_status = 'not_configured'
                storage_error = None
            
            return {
                'storage': {
                    'status': storage_status,
                    'backend': storage_backend,
                    'error': storage_error if 'error' in locals() else None,
                }
            }
            
        except Exception as e:
            logger.error(f"Storage health check failed: {e}")
            return {
                'storage': {
                    'status': 'unknown',
                    'error': str(e),
                }
            }
    
    def _check_auth_features(self) -> Dict[str, Any]:
        """Check authentication features status"""
        features = {
            'oidc_enabled': getattr(settings, 'OAUTH2_PROVIDER', {}).get('OIDC_ENABLED', False),
            'social_auth_enabled': 'social_django' in settings.INSTALLED_APPS,
            'token_auth_enabled': 'rest_framework.authtoken' in settings.INSTALLED_APPS,
            'jwt_auth_enabled': getattr(settings, 'REST_FRAMEWORK', {}).get('DEFAULT_AUTHENTICATION_CLASSES', []),
        }
        
        # Check configured social providers
        social_providers = []
        provider_configs = [
            ('SOCIAL_AUTH_GOOGLE_OAUTH2_KEY', 'google-oauth2'),
            ('SOCIAL_AUTH_FACEBOOK_KEY', 'facebook'),
            ('SOCIAL_AUTH_GITHUB_KEY', 'github'),
            ('SOCIAL_AUTH_MICROSOFT_KEY', 'microsoft-graph'),
            ('SOCIAL_AUTH_LINKEDIN_KEY', 'linkedin'),
            ('SOCIAL_AUTH_AZUREAD_OAUTH2_KEY', 'azuread-oauth2'),
            ('SOCIAL_AUTH_OKTA_OAUTH2_KEY', 'okta-oauth2'),
            ('SOCIAL_AUTH_OIDC_KEY', 'openid-connect'),
        ]
        
        for config_key, provider_name in provider_configs:
            if getattr(settings, config_key, None):
                social_providers.append(provider_name)
        
        features['social_providers'] = social_providers
        features['social_providers_count'] = len(social_providers)
        
        return {'features': features}
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        import psutil
        
        try:
            # Python info
            python_info = {
                'version': sys.version,
                'implementation': platform.python_implementation(),
                'compiler': platform.python_compiler(),
            }
            
            # System info
            system_info = {
                'platform': platform.platform(),
                'system': platform.system(),
                'release': platform.release(),
                'machine': platform.machine(),
                'processor': platform.processor(),
            }
            
            # Resource usage
            try:
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                resources = {
                    'cpu_count': psutil.cpu_count(),
                    'memory_total': memory.total,
                    'memory_available': memory.available,
                    'memory_percent': memory.percent,
                    'disk_total': disk.total,
                    'disk_used': disk.used,
                    'disk_free': disk.free,
                    'disk_percent': disk.percent,
                }
            except (ImportError, AttributeError):
                resources = {'available': False}
            
            # Django info
            django_info = {
                'version': self._get_django_version(),
                'debug': settings.DEBUG,
                'timezone': str(settings.TIME_ZONE),
                'allowed_hosts': len(settings.ALLOWED_HOSTS),
                'installed_apps_count': len(settings.INSTALLED_APPS),
            }
            
            return {
                'system': {
                    'python': python_info,
                    'os': system_info,
                    'resources': resources,
                    'django': django_info,
                }
            }
            
        except Exception as e:
            logger.error(f"System info collection failed: {e}")
            return {
                'system': {
                    'status': 'partial',
                    'error': str(e),
                }
            }
    
    def _get_django_version(self) -> str:
        """Get Django version"""
        import django
        return django.get_version()


class SystemInfoView(APIView):
    """
    Get detailed system information (admin only)
    
    GET /api/system/info/
    """
    permission_classes = [IsAdminUser]
    throttle_classes = [UserRateThrottle]
    
    def get(self, request):
        """Get comprehensive system information"""
        try:
            info = {
                'timestamp': timezone.now().isoformat(),
                'service': {
                    'name': 'Organization SSO',
                    'version': getattr(settings, 'APP_VERSION', '1.0.0'),
                    'environment': settings.DEBUG and 'development' or 'production',
                    'build_date': getattr(settings, 'BUILD_DATE', 'unknown'),
                    'commit_hash': getattr(settings, 'COMMIT_HASH', 'unknown'),
                },
                'django': {
                    'version': self._get_django_version(),
                    'debug': settings.DEBUG,
                    'timezone': str(settings.TIME_ZONE),
                    'language_code': settings.LANGUAGE_CODE,
                    'site_id': settings.SITE_ID,
                    'secret_key_set': bool(settings.SECRET_KEY),
                },
                'database': {
                    'engine': connection.vendor,
                    'name': connection.settings_dict.get('NAME', 'unknown'),
                    'host': connection.settings_dict.get('HOST', 'unknown'),
                    'port': connection.settings_dict.get('PORT', 'unknown'),
                },
                'authentication': {
                    'backends': settings.AUTHENTICATION_BACKENDS,
                    'oauth2_provider': {
                        'enabled': 'oauth2_provider' in settings.INSTALLED_APPS,
                        'oidc_enabled': getattr(settings, 'OAUTH2_PROVIDER', {}).get('OIDC_ENABLED', False),
                    },
                    'social_auth': {
                        'enabled': 'social_django' in settings.INSTALLED_APPS,
                        'providers': self._get_configured_providers(),
                    },
                },
                'security': {
                    'https_only': getattr(settings, 'SECURE_SSL_REDIRECT', False),
                    'csrf_cookie_secure': getattr(settings, 'CSRF_COOKIE_SECURE', False),
                    'session_cookie_secure': getattr(settings, 'SESSION_COOKIE_SECURE', False),
                    'allowed_hosts': settings.ALLOWED_HOSTS,
                    'csrf_trusted_origins': getattr(settings, 'CSRF_TRUSTED_ORIGINS', []),
                    'cors_allowed_origins': getattr(settings, 'CORS_ALLOWED_ORIGINS', []),
                },
                'urls': {
                    'admin': request.build_absolute_uri('/admin/'),
                    'api_root': request.build_absolute_uri('/api/'),
                    'oidc_discovery': request.build_absolute_uri('/.well-known/openid-configuration'),
                    'swagger': request.build_absolute_uri('/api/docs/') if 'drf_yasg' in settings.INSTALLED_APPS else None,
                },
            }
            
            # Add statistics if requested
            if request.query_params.get('include_stats', 'false').lower() == 'true':
                info['statistics'] = self._get_system_stats()
            
            return Response(info)
            
        except Exception as e:
            logger.error(f"System info retrieval failed: {e}", exc_info=True)
            return Response(
                {'error': 'Failed to retrieve system information'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _get_configured_providers(self) -> Dict[str, bool]:
        """Get status of configured social providers"""
        providers = {}
        config_mapping = {
            'google-oauth2': 'SOCIAL_AUTH_GOOGLE_OAUTH2_KEY',
            'facebook': 'SOCIAL_AUTH_FACEBOOK_KEY',
            'github': 'SOCIAL_AUTH_GITHUB_KEY',
            'microsoft-graph': 'SOCIAL_AUTH_MICROSOFT_KEY',
            'linkedin': 'SOCIAL_AUTH_LINKEDIN_KEY',
            'azuread-oauth2': 'SOCIAL_AUTH_AZUREAD_OAUTH2_KEY',
            'okta-oauth2': 'SOCIAL_AUTH_OKTA_OAUTH2_KEY',
            'openid-connect': 'SOCIAL_AUTH_OIDC_KEY',
        }
        
        for provider, config_key in config_mapping.items():
            providers[provider] = bool(getattr(settings, config_key, None))
        
        return providers
    
    def _get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        stats = {
            'users': {
                'total': User.objects.count(),
                'active': User.objects.filter(is_active=True).count(),
                'staff': User.objects.filter(is_staff=True).count(),
                'superusers': User.objects.filter(is_superuser=True).count(),
                'social_users': SocialConnection.objects.filter(is_active=True)
                                .values('user_id').distinct().count(),
            },
            'organizations': {
                'total': Organization.objects.count(),
                'active': Organization.objects.filter(is_active=True).count(),
            },
            'departments': Department.objects.count(),
            'social_connections': SocialConnection.objects.filter(is_active=True).count(),
            'applications': Application.objects.count(),
            'recent_logins': SocialLoginEvent.objects.filter(
                event_type='login',
                created_at__gte=timezone.now() - timezone.timedelta(hours=24)
            ).count(),
        }
        
        return stats


class MetricsView(APIView):
    """
    System metrics for monitoring (Prometheus format)
    
    GET /api/metrics/
    """
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        """Return metrics in Prometheus format"""
        try:
            metrics = []
            
            # User metrics
            total_users = User.objects.count()
            active_users = User.objects.filter(is_active=True).count()
            
            metrics.extend([
                f'sso_users_total {total_users}',
                f'sso_users_active {active_users}',
                f'sso_users_inactive {total_users - active_users}',
            ])
            
            # Social auth metrics
            social_users = SocialConnection.objects.filter(is_active=True).values('user_id').distinct().count()
            total_connections = SocialConnection.objects.filter(is_active=True).count()
            
            metrics.extend([
                f'sso_social_users_total {social_users}',
                f'sso_social_connections_total {total_connections}',
            ])
            
            # Recent activity
            hour_ago = timezone.now() - timezone.timedelta(hours=1)
            recent_logins = SocialLoginEvent.objects.filter(
                event_type='login',
                created_at__gte=hour_ago
            ).count()
            
            recent_failed_logins = SocialLoginEvent.objects.filter(
                event_type='login',
                success=False,
                created_at__gte=hour_ago
            ).count()
            
            metrics.extend([
                f'sso_logins_last_hour {recent_logins}',
                f'sso_failed_logins_last_hour {recent_failed_logins}',
            ])
            
            # OAuth applications
            app_count = Application.objects.count()
            metrics.append(f'sso_oauth_applications_total {app_count}')
            
            # Response
            response = Response('\n'.join(metrics))
            response['Content-Type'] = 'text/plain; version=0.0.4'
            return response
            
        except Exception as e:
            logger.error(f"Metrics collection failed: {e}", exc_info=True)
            return Response(
                f'sso_metrics_error{{error="{str(e)}"}} 1\n',
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content_type='text/plain'
            )


class ClientRegistrationView(APIView):
    """
    Register new OAuth2/OIDC client application
    
    POST /api/clients/register/
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    
    def post(self, request):
        """Register a new OAuth2 client"""
        from oauth2_provider.models import Application
        
        # Use serializer for validation
        serializer = ClientRegistrationSerializer(data=request.data, context={'request': request})
        
        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Create the application
            application = serializer.save()
            
            logger.info(
                f"New OAuth2 client registered: {application.name} "
                f"(client_id: {application.client_id}) by user {request.user.id}"
            )
            
            # Create audit event
            SocialLoginEvent.objects.create(
                user=request.user,
                event_type='connect',  # Reusing for client registration
                provider='oauth2',
                email_attempted=request.user.email,
                success=True,
                ip_address=request.META.get('REMOTE_ADDR', ''),
                extra_data={
                    'action': 'client_registered',
                    'client_id': application.client_id,
                    'client_name': application.name,
                    'grant_type': application.authorization_grant_type,
                }
            )
            
            # Return response with client credentials
            response_data = {
                'client_id': application.client_id,
                'client_secret': application.client_secret,
                'client_id_issued_at': int(application.created.timestamp()),
                'client_secret_expires_at': 0,  # Never expires
                'registration_access_token': self._generate_registration_token(application),
                'registration_client_uri': request.build_absolute_uri(
                    f'/api/clients/{application.client_id}/'
                ),
                'metadata': serializer.data,
            }
            
            return Response(response_data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Client registration failed: {e}", exc_info=True)
            return Response(
                {'error': f'Failed to register client: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def _generate_registration_token(self, application) -> str:
        """Generate a registration access token (simplified)"""
        import hashlib
        import secrets
        
        # Generate a simple token for client management
        raw_token = f"{application.client_id}:{application.client_secret}:{secrets.token_urlsafe(32)}"
        return hashlib.sha256(raw_token.encode()).hexdigest()


class ClientManagementView(APIView):
    """
    Manage OAuth2 client applications
    
    GET /api/clients/ - List user's clients
    GET /api/clients/{client_id}/ - Get client details
    PUT /api/clients/{client_id}/ - Update client
    DELETE /api/clients/{client_id}/ - Delete client
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    
    def get(self, request, client_id=None):
        """List or get client details"""
        from oauth2_provider.models import Application
        
        if client_id:
            # Get specific client
            try:
                application = Application.objects.get(
                    client_id=client_id,
                    user=request.user
                )
                serializer = ClientRegistrationSerializer(application)
                return Response(serializer.data)
            except Application.DoesNotExist:
                return Response(
                    {'error': 'Client not found or access denied'},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            # List user's clients
            applications = Application.objects.filter(user=request.user)
            serializer = ClientRegistrationSerializer(applications, many=True)
            return Response({
                'clients': serializer.data,
                'count': applications.count(),
            })
    
    def put(self, request, client_id):
        """Update client"""
        from oauth2_provider.models import Application
        
        try:
            application = Application.objects.get(
                client_id=client_id,
                user=request.user
            )
            
            serializer = ClientRegistrationSerializer(
                application, 
                data=request.data, 
                partial=True,
                context={'request': request}
            )
            
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            updated_app = serializer.save()
            
            logger.info(f"OAuth2 client updated: {client_id} by user {request.user.id}")
            
            return Response(serializer.data)
            
        except Application.DoesNotExist:
            return Response(
                {'error': 'Client not found or access denied'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Client update failed: {e}", exc_info=True)
            return Response(
                {'error': f'Failed to update client: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def delete(self, request, client_id):
        """Delete client"""
        from oauth2_provider.models import Application
        
        try:
            application = Application.objects.get(
                client_id=client_id,
                user=request.user
            )
            
            client_name = application.name
            application.delete()
            
            logger.info(f"OAuth2 client deleted: {client_id} ({client_name}) by user {request.user.id}")
            
            return Response({
                'message': 'Client deleted successfully',
                'client_id': client_id,
                'client_name': client_name,
            })
            
        except Application.DoesNotExist:
            return Response(
                {'error': 'Client not found or access denied'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Client deletion failed: {e}", exc_info=True)
            return Response(
                {'error': f'Failed to delete client: {str(e)}'},
                status=status.HTP_400_BAD_REQUEST
            )


class APIRootView(APIView):
    """
    API root endpoint with documentation links
    
    GET /api/
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Return API information and available endpoints"""
        base_url = request.build_absolute_uri('/').rstrip('/')
        
        api_info = {
            'name': 'Organization SSO API',
            'version': getattr(settings, 'API_VERSION', '1.0.0'),
            'description': 'Single Sign-On and Identity Management API',
            'documentation': {
                'openapi': f'{base_url}/api/docs/',
                'redoc': f'{base_url}/api/redoc/',
                'oidc_discovery': f'{base_url}/.well-known/openid-configuration',
            },
            'endpoints': {
                'authentication': {
                    'login': f'{base_url}/api/users/login/',
                    'logout': f'{base_url}/api/users/logout/',
                    'register': f'{base_url}/api/users/register/',
                    'profile': f'{base_url}/api/users/profile/',
                },
                'oauth2': {
                    'authorize': f'{base_url}/o/authorize/',
                    'token': f'{base_url}/o/token/',
                    'revoke': f'{base_url}/o/revoke/',
                    'introspect': f'{base_url}/o/introspect/',
                },
                'oidc': {
                    'userinfo': f'{base_url}/api/oidc/userinfo/',
                    'jwks': f'{base_url}/api/oidc/jwks/',
                    'client_registration': f'{base_url}/api/clients/register/',
                },
                'social': {
                    'providers': f'{base_url}/api/social/providers/',
                    'connections': f'{base_url}/api/social/connections/',
                },
                'system': {
                    'health': f'{base_url}/api/health/',
                    'metrics': f'{base_url}/api/metrics/',
                    'info': f'{base_url}/api/system/info/',
                },
            },
            'authentication_methods': [
                'Bearer Token',
                'Session',
                'OAuth2',
                'OpenID Connect',
            ],
            'contact': {
                'email': getattr(settings, 'API_CONTACT_EMAIL', 'api@example.com'),
                'documentation': getattr(settings, 'API_DOCS_URL', ''),
            },
        }
        
        return Response(api_info)


@api_view(['GET'])
@permission_classes([AllowAny])
@throttle_classes([AnonRateThrottle])
def robots_txt(request):
    """
    robots.txt endpoint
    
    GET /robots.txt
    """
    content = """User-agent: *
Disallow: /admin/
Disallow: /api/health/
Disallow: /api/metrics/
Disallow: /api/system/

# Allow API documentation
Allow: /api/docs/
Allow: /api/redoc/

# Allow OIDC discovery
Allow: /.well-known/

Sitemap: https://yoursite.com/sitemap.xml
"""
    
    return Response(content, content_type='text/plain')


@api_view(['GET'])
@permission_classes([AllowAny])
def security_txt(request):
    """
    security.txt endpoint (RFC 9116)
    
    GET /.well-known/security.txt
    """
    content = f"""Contact: mailto:{getattr(settings, 'SECURITY_CONTACT_EMAIL', 'security@example.com')}
Expires: {datetime.now().replace(year=datetime.now().year + 1).strftime('%Y-%m-%dT%H:%M:%S.%fZ')}
Preferred-Languages: en
Acknowledgments: https://yoursite.com/security/acknowledgements
Policy: https://yoursite.com/security/policy
Signature: https://yoursite.com/.well-known/security.txt.sig
"""
    
    response = Response(content, content_type='text/plain')
    response['Content-Disposition'] = 'inline'
    return response