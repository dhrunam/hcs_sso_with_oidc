# apps/oidc/views/client.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
import logging
from ..serializers import ClientRegistrationSerializer
from ..throttles import RegistrationThrottle

logger = logging.getLogger(__name__)

class ClientRegistrationView(APIView):
    """Dynamic Client Registration (OIDC Registration 1.0)"""
    permission_classes = [IsAuthenticated]
    throttle_classes = [RegistrationThrottle]
    
    def post(self, request):
        """Register a new OAuth client dynamically"""
        serializer = ClientRegistrationSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if not serializer.is_valid():
            return Response(
                {"error": "invalid_client_metadata", "error_description": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            application = serializer.save()
            
            # Prepare response according to RFC 7591
            response_data = {
                "client_id": application.client_id,
                "client_secret": application.client_secret,
                "client_id_issued_at": int(application.created.timestamp()),
                "client_secret_expires_at": 0,  # 0 means never expires
                "client_name": application.name,
                "redirect_uris": application.redirect_uris.split(),
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "application_type": "web",
                "token_endpoint_auth_method": "client_secret_basic",
            }
            
            # Add optional fields from request
            optional_fields = [
                'client_uri', 'logo_uri', 'scope', 'contacts',
                'tos_uri', 'policy_uri', 'jwks_uri', 'jwks'
            ]
            
            for field in optional_fields:
                if field in request.data:
                    response_data[field] = request.data[field]
            
            logger.info(f"New client registered: {application.client_id} by user {request.user.id}")
            return Response(response_data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Client registration failed: {e}")
            return Response(
                {"error": "invalid_client_metadata", "error_description": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )