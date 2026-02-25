import logging

from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser
from rest_framework import status

from django.contrib.auth.models import User
from apps.social.models import SocialConnection, SocialLoginEvent
from oauth2_provider.models import Application

logger = logging.getLogger(__name__)


class MetricsView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        try:
            metrics = []

            total_users = User.objects.count()
            active_users = User.objects.filter(is_active=True).count()

            metrics.extend([
                f'sso_users_total {total_users}',
                f'sso_users_active {active_users}',
                f'sso_users_inactive {total_users - active_users}',
            ])

            social_users = SocialConnection.objects.filter(is_active=True).values('user_id').distinct().count()
            total_connections = SocialConnection.objects.filter(is_active=True).count()

            metrics.extend([
                f'sso_social_users_total {social_users}',
                f'sso_social_connections_total {total_connections}',
            ])

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

            app_count = Application.objects.count()
            metrics.append(f'sso_oauth_applications_total {app_count}')

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
