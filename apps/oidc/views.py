# # apps/oidc/views.py - COMPLETE VERSION
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.permissions import AllowAny, IsAuthenticated
# from rest_framework import status
# from django.conf import settings
# from cryptography.hazmat.primitives import serialization
# from oauth2_provider.models import AccessToken, RefreshToken, Application
# from django.utils import timezone
# from django.contrib.auth import get_user_model
# import json
# import base64
# import hashlib
# import jwt
# from datetime import datetime

# User = get_user_model()

# class JWKSDocumentView(APIView):
#     """JSON Web Key Set document for OIDC (RFC 7517)"""
#     permission_classes = [AllowAny]
    
#     def get(self, request):
#         try:
#             # Load public key
#             public_key_path = settings.BASE_DIR / 'oidc_public_key.pem'
#             with open(public_key_path, 'rb') as f:
#                 public_key = serialization.load_pem_public_key(f.read())
            
#             # Extract RSA parameters
#             public_numbers = public_key.public_numbers()
            
#             # Convert to JWK format
#             jwks = {
#                 "keys": [{
#                     "kty": "RSA",
#                     "use": "sig",
#                     "kid": "1",
#                     "n": self.int_to_base64(public_numbers.n),
#                     "e": self.int_to_base64(public_numbers.e),
#                     "alg": "RS256",
#                 }]
#             }
            
#             return Response(jwks)
            
#         except FileNotFoundError:
#             return Response(
#                 {"error": "Public key not found"},
#                 status=status.HTTP_503_SERVICE_UNAVAILABLE
#             )
#         except Exception as e:
#             return Response(
#                 {"error": f"JWKS generation failed: {str(e)}"},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )
    
#     def int_to_base64(self, number):
#         """Convert integer to Base64URL"""
#         byte_length = (number.bit_length() + 7) // 8
#         bytes_val = number.to_bytes(byte_length, 'big')
#         return base64.urlsafe_b64encode(bytes_val).decode('utf-8').rstrip('=')

# class OIDCProviderInfoView(APIView):
#     """OIDC Discovery Document (OpenID Connect Discovery 1.0)"""
#     permission_classes = [AllowAny]
    
#     def get(self, request):
#         base_url = request.build_absolute_uri('/').rstrip('/')
        
#         provider_info = {
#             # REQUIRED: Issuer identifier
#             "issuer": f"{base_url}/o",
            
#             # REQUIRED: Authorization endpoint
#             "authorization_endpoint": f"{base_url}/o/authorize/",
            
#             # REQUIRED: Token endpoint  
#             "token_endpoint": f"{base_url}/o/token/",
            
#             # REQUIRED: UserInfo endpoint
#             "userinfo_endpoint": f"{base_url}/api/oidc/userinfo/",
            
#             # REQUIRED: JWKS endpoint
#             "jwks_uri": f"{base_url}/api/oidc/jwks/",
            
#             # REQUIRED: Supported scopes
#             "scopes_supported": ["openid", "profile", "email", "offline_access", "read", "write"],
            
#             # REQUIRED: Supported response types
#             "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
            
#             # RECOMMENDED: Supported response modes
#             "response_modes_supported": ["query", "fragment"],
            
#             # RECOMMENDED: Supported grant types
#             "grant_types_supported": ["authorization_code", "implicit", "password", "client_credentials", "refresh_token"],
            
#             # REQUIRED: Supported subject types
#             "subject_types_supported": ["public"],
            
#             # REQUIRED: Supported ID token signing algorithms
#             "id_token_signing_alg_values_supported": ["RS256"],
            
#             # OPTIONAL: Token endpoint auth methods
#             "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            
#             # RECOMMENDED: Supported claims
#             "claims_supported": ["sub", "name", "given_name", "family_name", "preferred_username", "email", "email_verified"],
            
#             # RECOMMENDED: Code challenge methods (PKCE)
#             "code_challenge_methods_supported": ["S256", "plain"],
            
#             # OPTIONAL: End session endpoint
#             "end_session_endpoint": f"{base_url}/o/authorize/logout/",
            
#             # OPTIONAL: Check session iframe
#             "check_session_iframe": f"{base_url}/o/checksession/",
            
#             # OPTIONAL: Revocation endpoint (RFC 7009)
#             "revocation_endpoint": f"{base_url}/api/oidc/revoke/",
            
#             # OPTIONAL: Introspection endpoint (RFC 7662)
#             "introspection_endpoint": f"{base_url}/api/oidc/introspect/",
            
#             # OPTIONAL: Registration endpoint
#             "registration_endpoint": f"{base_url}/o/applications/",
            
#             # OPTIONAL: Service documentation
#             "service_documentation": f"{base_url}/docs/",
            
#             # OPTIONAL: UI locales supported
#             "ui_locales_supported": ["en"],
            
#             # OPTIONAL: OP policy URI
#             "op_policy_uri": f"{base_url}/policy/",
            
#             # OPTIONAL: OP terms of service URI
#             "op_tos_uri": f"{base_url}/terms/",
#         }
        
#         return Response(provider_info)

# class OIDCUserInfoView(APIView):
#     """OIDC UserInfo Endpoint (OpenID Connect Core 1.0)"""
#     permission_classes = [IsAuthenticated]
    
#     def get(self, request):
#         """GET method for UserInfo"""
#         return self._get_user_info(request)
    
#     def post(self, request):
#         """POST method for UserInfo (for access tokens in body)"""
#         return self._get_user_info(request)
    
#     def _get_user_info(self, request):
#         """Extract and return user info based on token scope"""
#         from apps.oidc.validators import CustomOAuth2Validator
        
#         try:
#             # Create a mock request for the validator
#             class MockRequest:
#                 def __init__(self, user, scopes):
#                     self.user = user
#                     self.scopes = scopes
            
#             # Get scopes from token
#             token = self._get_token_from_request(request)
#             scopes = token.scope.split() if token else ['openid']
            
#             mock_request = MockRequest(request.user, scopes)
#             validator = CustomOAuth2Validator()
            
#             # Get claims based on scope
#             claims = validator.get_userinfo_claims(mock_request)
            
#             return Response(claims)
            
#         except Exception as e:
#             return Response(
#                 {"error": f"Failed to get user info: {str(e)}"},
#                 status=status.HTTP_400_BAD_REQUEST
#             )
    
#     def _get_token_from_request(self, request):
#         """Extract token from request"""
#         # Try Authorization header first
#         auth_header = request.headers.get('Authorization')
#         if auth_header and auth_header.startswith('Bearer '):
#             token_string = auth_header.split(' ')[1]
#             try:
#                 return AccessToken.objects.get(token=token_string)
#             except AccessToken.DoesNotExist:
#                 pass
        
#         # Try access_token parameter (for POST requests)
#         token_string = request.data.get('access_token') or request.query_params.get('access_token')
#         if token_string:
#             try:
#                 return AccessToken.objects.get(token=token_string)
#             except AccessToken.DoesNotExist:
#                 pass
        
#         return None

# class TokenIntrospectionView(APIView):
#     """OAuth 2.0 Token Introspection (RFC 7662)"""
#     permission_classes = [AllowAny]  # Usually requires client authentication
    
#     def post(self, request):
#         """Introspect token and return status"""
#         token_string = request.data.get('token')
#         token_type_hint = request.data.get('token_type_hint', 'access_token')
        
#         if not token_string:
#             return Response(
#                 {"error": "token parameter is required"},
#                 status=status.HTTP_400_BAD_REQUEST
#             )
        
#         # Authenticate client (simplified - in production, use proper client auth)
#         client_id = request.data.get('client_id')
#         client_secret = request.data.get('client_secret')
        
#         if not self._authenticate_client(client_id, client_secret):
#             return Response(
#                 {"error": "invalid_client"},
#                 status=status.HTTP_401_UNAUTHORIZED
#             )
        
#         # Look for token
#         token = None
#         token_type = None
        
#         # Check access tokens
#         try:
#             token = AccessToken.objects.get(token=token_string)
#             token_type = 'access_token'
#         except AccessToken.DoesNotExist:
#             pass
        
#         # Check refresh tokens
#         if not token:
#             try:
#                 token = RefreshToken.objects.get(token=token_string)
#                 token_type = 'refresh_token'
#             except RefreshToken.DoesNotExist:
#                 pass
        
#         if not token:
#             return Response({"active": False})
        
#         # Check if token is expired
#         now = timezone.now()
#         if token.expires < now:
#             return Response({
#                 "active": False,
#                 "exp": int(token.expires.timestamp()),
#             })
        
#         # Token is active
#         response = {
#             "active": True,
#             "scope": token.scope,
#             "client_id": token.application.client_id if token.application else "",
#             "username": token.user.username,
#             "token_type": token_type,
#             "exp": int(token.expires.timestamp()),
#             "iat": int(token.created.timestamp()),
#             "sub": str(token.user.id),
#             "aud": token.application.client_id if token.application else "",
#             "iss": request.build_absolute_uri('/o'),
#         }
        
#         # Add OIDC claims if available
#         if hasattr(token, 'identity_provider'):
#             response['identity_provider'] = token.identity_provider
        
#         return Response(response)
    
#     def _authenticate_client(self, client_id, client_secret):
#         """Simple client authentication (enhance for production)"""
#         if not client_id or not client_secret:
#             return False
        
#         try:
#             app = Application.objects.get(client_id=client_id)
#             return app.client_secret == client_secret
#         except Application.DoesNotExist:
#             return False

# class TokenRevocationView(APIView):
#     """OAuth 2.0 Token Revocation (RFC 7009)"""
#     permission_classes = [IsAuthenticated]  # Or client authentication
    
#     def post(self, request):
#         """Revoke a token"""
#         token_string = request.data.get('token')
#         token_type_hint = request.data.get('token_type_hint', 'access_token')
        
#         if not token_string:
#             return Response(
#                 {"error": "token parameter is required"},
#                 status=status.HTTP_400_BAD_REQUEST
#             )
        
#         revoked = False
        
#         # Try to revoke access token
#         try:
#             token = AccessToken.objects.get(token=token_string)
#             token.delete()
#             revoked = True
#         except AccessToken.DoesNotExist:
#             pass
        
#         # Try to revoke refresh token
#         if not revoked:
#             try:
#                 token = RefreshToken.objects.get(token=token_string)
#                 token.delete()
#                 revoked = True
#             except RefreshToken.DoesNotExist:
#                 pass
        
#         return Response({"revoked": revoked})

# class ClientRegistrationView(APIView):
#     """Dynamic Client Registration (OIDC Registration 1.0)"""
#     permission_classes = [IsAuthenticated]
    
#     def post(self, request):
#         """Register a new OAuth client dynamically"""
#         from oauth2_provider.models import Application
        
#         # Required fields according to OIDC Dynamic Client Registration
#         required_fields = ['client_name', 'redirect_uris']
        
#         for field in required_fields:
#             if field not in request.data:
#                 return Response(
#                     {"error": f"Missing required field: {field}"},
#                     status=status.HTTP_400_BAD_REQUEST
#                 )
        
#         try:
#             # Create application
#             application = Application.objects.create(
#                 name=request.data['client_name'],
#                 user=request.user,
#                 client_type=request.data.get('application_type', 'web'),
#                 authorization_grant_type='authorization-code',
#                 redirect_uris=request.data['redirect_uris'],
#                 skip_authorization=request.data.get('skip_authorization', False),
#             )
            
#             # Prepare response according to RFC 7591
#             response_data = {
#                 "client_id": application.client_id,
#                 "client_secret": application.client_secret,
#                 "client_id_issued_at": int(application.created.timestamp()),
#                 "client_secret_expires_at": 0,  # 0 means never expires
#                 "client_name": application.name,
#                 "redirect_uris": application.redirect_uris.split(),
#                 "grant_types": ["authorization_code", "refresh_token"],
#                 "response_types": ["code"],
#                 "application_type": "web",
#                 "token_endpoint_auth_method": "client_secret_basic",
#             }
            
#             # Add optional fields if provided
#             optional_fields = [
#                 'client_uri', 'logo_uri', 'scope', 'contacts',
#                 'tos_uri', 'policy_uri', 'jwks_uri', 'jwks'
#             ]
            
#             for field in optional_fields:
#                 if field in request.data:
#                     response_data[field] = request.data[field]
            
#             return Response(response_data, status=status.HTTP_201_CREATED)
            
#         except Exception as e:
#             return Response(
#                 {"error": f"Failed to create client: {str(e)}"},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

# class SessionManagementView(APIView):
#     """OIDC Session Management (Optional)"""
#     permission_classes = [IsAuthenticated]
    
#     def get(self, request):
#         """Get user's active sessions"""
#         active_tokens = AccessToken.objects.filter(
#             user=request.user,
#             expires__gt=timezone.now()
#         ).select_related('application')
        
#         sessions = []
#         for token in active_tokens:
#             sessions.append({
#                 'id': token.id,
#                 'application': token.application.name if token.application else 'Unknown',
#                 'scopes': token.scope,
#                 'created': token.created,
#                 'expires': token.expires,
#                 'identity_provider': getattr(token, 'identity_provider', 'local'),
#             })
        
#         return Response({
#             'user_id': request.user.id,
#             'email': request.user.email,
#             'active_sessions': sessions,
#             'total_sessions': len(sessions),
#         })
    
#     def delete(self, request, session_id=None):
#         """End a specific session or all sessions"""
#         if session_id:
#             # End specific session
#             try:
#                 token = AccessToken.objects.get(id=session_id, user=request.user)
#                 token.delete()
#                 return Response({"message": "Session ended"})
#             except AccessToken.DoesNotExist:
#                 return Response(
#                     {"error": "Session not found"},
#                     status=status.HTTP_404_NOT_FOUND
#                 )
#         else:
#             # End all sessions
#             AccessToken.objects.filter(user=request.user).delete()
#             RefreshToken.objects.filter(user=request.user).delete()
#             return Response({"message": "All sessions ended"})