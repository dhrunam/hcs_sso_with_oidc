# apps/oidc/views/token.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from oauth2_provider.models import AccessToken, RefreshToken, Application
from oauth2_provider.oauth2_backends import OAuthLibCore
from django.utils import timezone
import logging
from ..serializers import (
    IntrospectionRequestSerializer,
    RevocationRequestSerializer,
    SessionSerializer
)
from ..throttles import IntrospectionThrottle
from ..permissions import IsOAuth2Authenticated, IsClientAuthenticated

logger = logging.getLogger(__name__)

class OIDCUserInfoView(APIView):
    """OIDC UserInfo Endpoint (OpenID Connect Core 1.0)"""
    
    def get_permissions(self):
        """Use OAuth2 token authentication"""
        return [IsOAuth2Authenticated()]
    
    def get(self, request):
        """GET method for UserInfo"""
        return self._get_user_info(request)
    
    def post(self, request):
        """POST method for UserInfo"""
        return self._get_user_info(request)
    
    def _get_user_info(self, request):
        """Extract and return user info based on token scope"""
        from apps.oidc.validators import CustomOAuth2Validator
        
        try:
            # Get scopes from token
            scopes = request.access_token.scope.split()
            
            # Create a mock request for the validator
            class MockRequest:
                def __init__(self, user, scopes):
                    self.user = user
                    self.scopes = scopes
            
            mock_request = MockRequest(request.user, scopes)
            validator = CustomOAuth2Validator()
            
            # Get claims based on scope
            claims = validator.get_userinfo_claims(mock_request)
            
            return Response(claims)
            
        except Exception as e:
            logger.error(f"UserInfo endpoint error: {e}")
            return Response(
                {"error": "server_error", "error_description": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class TokenIntrospectionView(APIView):
    """
    OAuth 2.0 Token Introspection (RFC 7662)
    
    Requires client authentication via HTTP Basic or POST credentials.
    Only the client that owns the token (or an admin) can introspect it.
    """
    permission_classes = [IsClientAuthenticated]
    throttle_classes = [IntrospectionThrottle]
    
    def post(self, request):
        """Introspect token and return status"""
        serializer = IntrospectionRequestSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {"error": "invalid_request", "error_description": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        data = serializer.validated_data
        token_string = data['token']
        token_type_hint = data.get('token_type_hint', 'access_token')
        application = data.get('application')
        
        # Look for token
        token = None
        token_type = None
        
        # Check access tokens
        try:
            token = AccessToken.objects.get(token=token_string)
            token_type = 'access_token'
        except AccessToken.DoesNotExist:
            pass
        
        # Check refresh tokens
        if not token and token_type_hint != 'access_token':
            try:
                token = RefreshToken.objects.get(token=token_string)
                token_type = 'refresh_token'
            except RefreshToken.DoesNotExist:
                pass
        
        if not token:
            return Response({"active": False})
        
        # Verify client owns the token (or is admin)
        # The introspecting client must match the token's application
        token_client = token.application
        caller_client = getattr(request, 'client_app', None)
        
        if caller_client and token_client and caller_client.id != token_client.id:
            # Client trying to introspect a token they didn't issue
            logger.warning(
                f"Unauthorized introspection attempt: client {caller_client.client_id} "
                f"trying to introspect token from client {token_client.client_id}"
            )
            return Response({"active": False})
        
        # Check if token is expired
        now = timezone.now()
        if token.expires < now:
            return Response({
                "active": False,
                "exp": int(token.expires.timestamp()),
            })
        
        # Token is active
        response = {
            "active": True,
            "scope": token.scope,
            "client_id": token.application.client_id if token.application else "",
            "username": token.user.username,
            "token_type": token_type,
            "exp": int(token.expires.timestamp()),
            "iat": int(token.created.timestamp()),
            "sub": str(token.user.id),
            "aud": token.application.client_id if token.application else "",
            "iss": request.build_absolute_uri('/o'),
        }
        
        # Add OIDC claims if available
        if hasattr(token, 'identity_provider'):
            response['identity_provider'] = token.identity_provider
        
        # Add user profile info
        if token.user and hasattr(token.user, 'profile'):
            profile = token.user.profile
            response['email_verified'] = profile.email_verified
            response['name'] = f"{token.user.first_name} {token.user.last_name}".strip()
            response['email'] = token.user.email
        
        return Response(response)


class TokenRevocationView(APIView):
    """
    OAuth 2.0 Token Revocation (RFC 7009)
    
    Requires client authentication via HTTP Basic or POST credentials.
    Clients can only revoke their own tokens.
    """
    permission_classes = [IsClientAuthenticated]
    
    def post(self, request):
        """Revoke a token"""
        serializer = RevocationRequestSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {"error": "invalid_request", "error_description": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        data = serializer.validated_data
        token_string = data['token']
        token_type_hint = data.get('token_type_hint')
        caller_client = getattr(request, 'client_app', None)
        
        revoked = False
        
        # Try to revoke access token first if hinted or not specified
        if not token_type_hint or token_type_hint == 'access_token':
            try:
                token = AccessToken.objects.get(token=token_string)
                
                # Verify caller owns this token
                if caller_client and token.application and caller_client.id != token.application.id:
                    logger.warning(
                        f"Unauthorized revocation attempt: client {caller_client.client_id} "
                        f"trying to revoke token from client {token.application.client_id}"
                    )
                    return Response({"revoked": False})
                
                token.delete()
                revoked = True
                logger.info(f"Access token revoked: {token_string[:10]}...")
            except AccessToken.DoesNotExist:
                pass
        
        # Try to revoke refresh token
        if not revoked and (not token_type_hint or token_type_hint == 'refresh_token'):
            try:
                token = RefreshToken.objects.get(token=token_string)
                
                # Verify caller owns this token
                if caller_client and token.application and caller_client.id != token.application.id:
                    logger.warning(
                        f"Unauthorized revocation attempt: client {caller_client.client_id} "
                        f"trying to revoke token from client {token.application.client_id}"
                    )
                    return Response({"revoked": False})
                
                token.delete()
                revoked = True
                logger.info(f"Refresh token revoked: {token_string[:10]}...")
            except RefreshToken.DoesNotExist:
                pass
        
        return Response({"revoked": revoked})


class SessionManagementView(APIView):
    """OIDC Session Management"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get user's active sessions"""
        active_tokens = AccessToken.objects.filter(
            user=request.user,
            expires__gt=timezone.now()
        ).select_related('application').order_by('-created')
        
        serializer = SessionSerializer(active_tokens, many=True)
        
        return Response({
            'user_id': request.user.id,
            'email': request.user.email,
            'active_sessions': serializer.data,
            'total_sessions': len(active_tokens),
        })
    
    def delete(self, request, session_id=None):
        """End a specific session or all sessions"""
        if session_id:
            # End specific session
            try:
                token = AccessToken.objects.get(id=session_id, user=request.user)
                token.delete()
                logger.info(f"Session {session_id} ended by user {request.user.id}")
                return Response({"message": "Session ended"})
            except AccessToken.DoesNotExist:
                return Response(
                    {"error": "session_not_found"},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            # End all sessions for this user
            count, _ = AccessToken.objects.filter(user=request.user).delete()
            RefreshToken.objects.filter(user=request.user).delete()
            logger.info(f"All sessions ({count}) ended for user {request.user.id}")
            return Response({
                "message": f"{count} sessions ended",
                "sessions_ended": count
            })