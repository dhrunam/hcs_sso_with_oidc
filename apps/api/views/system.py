import logging
from typing import Dict, Any

from django.conf import settings
from django.db import connection
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser
from rest_framework.throttling import UserRateThrottle
from rest_framework import status

from django.contrib.auth.models import User
from apps.core.models import Department, Organization
from apps.social.models import SocialConnection, SocialLoginEvent
from oauth2_provider.models import Application

logger = logging.getLogger(__name__)


class SystemInfoView(APIView):
    permission_classes = [IsAdminUser]
    throttle_classes = [UserRateThrottle]

    def get(self, request):
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

            if request.query_params.get('include_stats', 'false').lower() == 'true':
                info['statistics'] = self._get_system_stats()

            return Response(info)

        except Exception as e:
            logger.error(f"System info retrieval failed: {e}", exc_info=True)
            return Response(
                {'error': 'Failed to retrieve system information'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_django_version(self) -> str:
        import django
        return django.get_version()

    def _get_configured_providers(self) -> Dict[str, bool]:
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
        return {
            'users': {
                'total': User.objects.count(),
                'active': User.objects.filter(is_active=True).count(),
                'staff': User.objects.filter(is_staff=True).count(),
                'superusers': User.objects.filter(is_superuser=True).count(),
                'social_users': SocialConnection.objects.filter(is_active=True).values('user_id').distinct().count(),
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
