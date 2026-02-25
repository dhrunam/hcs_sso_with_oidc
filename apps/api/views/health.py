import logging
import platform
import sys
from typing import Dict, Any

from django.conf import settings
from django.core.cache import cache
from django.db import connection, DatabaseError
from django.utils import timezone
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.throttling import AnonRateThrottle

logger = logging.getLogger(__name__)


class HealthCheckView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def get(self, request):
        try:
            health_status = {
                'status': 'healthy',
                'timestamp': timezone.now().isoformat(),
                'service': 'organization-sso',
                'version': getattr(settings, 'APP_VERSION', '1.0.0'),
                'environment': settings.DEBUG and 'development' or 'production',
            }

            db_status = self._check_database()
            health_status.update(db_status)

            cache_status = self._check_cache()
            health_status.update(cache_status)

            storage_status = self._check_storage()
            health_status.update(storage_status)

            auth_features = self._check_auth_features()
            health_status.update(auth_features)

            system_info = self._get_system_info()
            health_status.update(system_info)

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
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()

            User.objects.exists()

            db_info = {
                'engine': connection.vendor,
                'name': connection.settings_dict.get('NAME', 'unknown'),
                'host': connection.settings_dict.get('HOST', 'unknown'),
                'port': connection.settings_dict.get('PORT', 'unknown'),
            }

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
        try:
            test_key = 'health_check_cache_test'
            test_value = timezone.now().isoformat()

            cache.set(test_key, test_value, 30)
            retrieved = cache.get(test_key)

            cache_status = 'healthy' if retrieved == test_value else 'degraded'

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
        try:
            storage_backend = getattr(settings, 'DEFAULT_FILE_STORAGE', '')

            if not storage_backend or 'FileSystemStorage' in storage_backend:
                import os
                import tempfile

                test_dir = settings.MEDIA_ROOT if hasattr(settings, 'MEDIA_ROOT') else tempfile.gettempdir()
                test_file = os.path.join(test_dir, 'health_check_test.txt')

                try:
                    with open(test_file, 'w') as file_handle:
                        file_handle.write('test')
                    os.remove(test_file)
                    storage_status = 'healthy'
                except (IOError, OSError) as e:
                    storage_status = 'unhealthy'
                    storage_error = str(e)
            else:
                storage_status = 'not_configured'
                storage_error = None

            return {
                'storage': {
                    'status': storage_status,
                    'backend': storage_backend,
                    'error': storage_error if 'storage_error' in locals() else None,
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
        features = {
            'oidc_enabled': getattr(settings, 'OAUTH2_PROVIDER', {}).get('OIDC_ENABLED', False),
            'social_auth_enabled': 'social_django' in settings.INSTALLED_APPS,
            'token_auth_enabled': 'rest_framework.authtoken' in settings.INSTALLED_APPS,
            'jwt_auth_enabled': getattr(settings, 'REST_FRAMEWORK', {}).get('DEFAULT_AUTHENTICATION_CLASSES', []),
        }

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
        try:
            import psutil

            python_info = {
                'version': sys.version,
                'implementation': platform.python_implementation(),
                'compiler': platform.python_compiler(),
            }

            system_info = {
                'platform': platform.platform(),
                'system': platform.system(),
                'release': platform.release(),
                'machine': platform.machine(),
                'processor': platform.processor(),
            }

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
        import django
        return django.get_version()
