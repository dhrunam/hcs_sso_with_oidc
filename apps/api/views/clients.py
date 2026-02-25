import logging

from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import UserRateThrottle
from rest_framework import status

from apps.social.models import SocialLoginEvent

logger = logging.getLogger(__name__)


def _get_client_registration_serializer():
    from apps.api.views import ClientRegistrationSerializer
    return ClientRegistrationSerializer


class ClientRegistrationView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def post(self, request):
        from oauth2_provider.models import Application
        serializer_class = _get_client_registration_serializer()

        serializer = serializer_class(data=request.data, context={'request': request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            application = serializer.save()

            logger.info(
                f"New OAuth2 client registered: {application.name} "
                f"(client_id: {application.client_id}) by user {request.user.id}"
            )

            SocialLoginEvent.objects.create(
                user=request.user,
                event_type='connect',
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

            response_data = {
                'client_id': application.client_id,
                'client_secret': application.client_secret,
                'client_id_issued_at': int(application.created.timestamp()),
                'client_secret_expires_at': 0,
                'registration_access_token': self._generate_registration_token(application),
                'registration_client_uri': request.build_absolute_uri(f'/api/clients/{application.client_id}/'),
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
        import hashlib
        import secrets
        raw_token = f"{application.client_id}:{application.client_secret}:{secrets.token_urlsafe(32)}"
        return hashlib.sha256(raw_token.encode()).hexdigest()


class ClientManagementView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get(self, request, client_id=None):
        from oauth2_provider.models import Application
        serializer_class = _get_client_registration_serializer()

        if client_id:
            try:
                application = Application.objects.get(client_id=client_id, user=request.user)
                serializer = serializer_class(application)
                return Response(serializer.data)
            except Application.DoesNotExist:
                return Response({'error': 'Client not found or access denied'}, status=status.HTTP_404_NOT_FOUND)
        else:
            applications = Application.objects.filter(user=request.user)
            serializer = serializer_class(applications, many=True)
            return Response({'clients': serializer.data, 'count': applications.count()})

    def put(self, request, client_id):
        from oauth2_provider.models import Application
        serializer_class = _get_client_registration_serializer()

        try:
            application = Application.objects.get(client_id=client_id, user=request.user)
            serializer = serializer_class(
                application,
                data=request.data,
                partial=True,
                context={'request': request}
            )

            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()
            logger.info(f"OAuth2 client updated: {client_id} by user {request.user.id}")
            return Response(serializer.data)

        except Application.DoesNotExist:
            return Response({'error': 'Client not found or access denied'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Client update failed: {e}", exc_info=True)
            return Response({'error': f'Failed to update client: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, client_id):
        from oauth2_provider.models import Application

        try:
            application = Application.objects.get(client_id=client_id, user=request.user)
            client_name = application.name
            application.delete()
            logger.info(f"OAuth2 client deleted: {client_id} ({client_name}) by user {request.user.id}")
            return Response({'message': 'Client deleted successfully', 'client_id': client_id, 'client_name': client_name})

        except Application.DoesNotExist:
            return Response({'error': 'Client not found or access denied'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Client deletion failed: {e}", exc_info=True)
            return Response({'error': f'Failed to delete client: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
