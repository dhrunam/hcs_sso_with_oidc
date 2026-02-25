import logging
import requests

from django.conf import settings
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

logger = logging.getLogger(__name__)


class BFFLoginSerializer(serializers.Serializer):
    authorization_code = serializers.CharField()
    code_verifier = serializers.CharField()
    redirect_uri = serializers.CharField()


class BFFTokenRefreshSerializer(serializers.Serializer):
    pass


class BFFLogoutSerializer(serializers.Serializer):
    pass


def exchange_authorization_code_for_tokens(authorization_code, code_verifier, redirect_uri):
    payload = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'client_id': settings.BFF_CLIENT_ID,
        'client_secret': settings.BFF_CLIENT_SECRET,
        'redirect_uri': redirect_uri,
        'code_verifier': code_verifier,
    }
    try:
        response = requests.post(settings.SSO_TOKEN_URL, data=payload, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Token exchange failed: {e}")
        raise


def refresh_access_token(refresh_token):
    payload = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': settings.BFF_CLIENT_ID,
        'client_secret': settings.BFF_CLIENT_SECRET,
    }
    try:
        response = requests.post(settings.SSO_TOKEN_URL, data=payload, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Token refresh failed: {e}")
        raise


def set_refresh_token_cookie(response, refresh_token, expires_in):
    max_age = int(expires_in) if expires_in else (30 * 24 * 60 * 60)
    response.set_cookie(
        key='refresh_token',
        value=refresh_token,
        max_age=max_age,
        secure=settings.SECURE_COOKIE_SECURE,
        httponly=True,
        samesite=settings.SECURE_COOKIE_SAMESITE,
    )


def clear_refresh_token_cookie(response):
    response.delete_cookie('refresh_token', samesite=settings.SECURE_COOKIE_SAMESITE)


class BFFLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
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
                {'access_token': access_token, 'expires_in': expires_in, 'token_type': token_type},
                status=status.HTTP_200_OK,
            )
            if refresh_token:
                set_refresh_token_cookie(response, refresh_token, expires_in)
            return response
        except requests.RequestException:
            return Response({'error': 'Failed to exchange authorization code'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error in BFF login: {e}")
            return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class BFFTokenRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            refresh_token = request.COOKIES.get('refresh_token')
            if not refresh_token:
                return Response({'error': 'No refresh_token in cookies. Please log in.'}, status=status.HTTP_401_UNAUTHORIZED)

            token_data = refresh_access_token(refresh_token)
            access_token = token_data.get('access_token')
            new_refresh_token = token_data.get('refresh_token', refresh_token)
            expires_in = token_data.get('expires_in', 3600)
            token_type = token_data.get('token_type', 'Bearer')

            response = Response(
                {'access_token': access_token, 'expires_in': expires_in, 'token_type': token_type},
                status=status.HTTP_200_OK,
            )
            if new_refresh_token:
                set_refresh_token_cookie(response, new_refresh_token, expires_in)
            return response
        except requests.RequestException:
            return Response({'error': 'Failed to refresh token'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error in BFF refresh: {e}")
            return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class BFFLogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
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
                        timeout=5,
                    )
                except Exception as e:
                    logger.warning(f"Token revocation failed: {e}")

            response = Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)
            clear_refresh_token_cookie(response)
            return response
        except Exception as e:
            logger.error(f"Unexpected error in BFF logout: {e}")
            return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class BFFAuthViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    @action(detail=False, methods=['post'], name='login')
    def login(self, request):
        return BFFLoginView().post(request)

    @action(detail=False, methods=['post'], name='refresh')
    def refresh(self, request):
        return BFFTokenRefreshView().post(request)

    @action(detail=False, methods=['post'], name='logout')
    def logout(self, request):
        return BFFLogoutView().post(request)
