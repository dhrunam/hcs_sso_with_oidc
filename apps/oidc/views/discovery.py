# apps/oidc/views/discovery.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from django.conf import settings
from django.core.cache import cache
import logging
from ..utils.jwks import generate_jwks_document
from ..throttles import JWKSThrottle

logger = logging.getLogger(__name__)

class JWKSDocumentView(APIView):
    """JSON Web Key Set document for OIDC (RFC 7517)"""
    permission_classes = [AllowAny]
    throttle_classes = [JWKSThrottle]
    
    def get(self, request):
        # Cache JWKS for 24 hours
        cache_key = 'oidc_jwks'
        jwks = cache.get(cache_key)
        
        if jwks is None:
            try:
                jwks = generate_jwks_document()
                cache.set(cache_key, jwks, timeout=86400)  # 24 hours
            except Exception as e:
                logger.error(f"JWKS generation failed: {e}")
                return Response(
                    {"error": "jwks_generation_failed"},
                    status=status.HTTP_503_SERVICE_UNAVAILABLE
                )
        
        return Response(jwks)


class OIDCProviderInfoView(APIView):
    """OIDC Discovery Document (OpenID Connect Discovery 1.0)"""
    permission_classes = [AllowAny]
    
    def get(self, request):
        base_url = request.build_absolute_uri('/').rstrip('/')
        
        # Cache discovery document for 1 hour
        cache_key = 'oidc_discovery'
        provider_info = cache.get(cache_key)
        
        if provider_info is None:
            provider_info = self._generate_provider_info(request)
            cache.set(cache_key, provider_info, timeout=3600)
        
        return Response(provider_info)
    
    def _generate_provider_info(self, request):
        """Generate OIDC provider configuration"""
        base_url = request.build_absolute_uri('/').rstrip('/')
        
        return {
            # REQUIRED fields
            "issuer": f"{base_url}/o",
            "authorization_endpoint": f"{base_url}/o/authorize/",
            "token_endpoint": f"{base_url}/o/token/",
            "userinfo_endpoint": f"{base_url}/api/oidc/userinfo/",
            "jwks_uri": f"{base_url}/api/oidc/jwks/",
            
            # Scopes
            "scopes_supported": [
                "openid", "profile", "email", "phone", "address",
                "offline_access", "read", "write", "custom", "org"
            ],
            
            # Response types
            "response_types_supported": [
                "code", "token", "id_token", "code token",
                "code id_token", "token id_token", "code token id_token"
            ],
            
            # Subject types
            "subject_types_supported": ["public"],
            
            # Algorithms
            "id_token_signing_alg_values_supported": ["RS256"],
            
            # RECOMMENDED fields
            "response_modes_supported": ["query", "fragment", "form_post"],
            "grant_types_supported": [
                "authorization_code", "implicit", "password",
                "client_credentials", "refresh_token"
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post", "client_secret_basic"
            ],
            
            # Claims
            "claims_supported": [
                "sub", "name", "given_name", "family_name",
                "preferred_username", "email", "email_verified",
                "picture", "phone_number", "address",
                "organization", "department", "employee_id"
            ],
            
            # PKCE
            "code_challenge_methods_supported": ["S256", "plain"],
            
            # OPTIONAL endpoints
            "end_session_endpoint": f"{base_url}/o/authorize/logout/",
            "check_session_iframe": f"{base_url}/o/checksession/",
            "revocation_endpoint": f"{base_url}/api/oidc/revoke/",
            "introspection_endpoint": f"{base_url}/api/oidc/introspect/",
            "registration_endpoint": f"{base_url}/api/oidc/register/",
            
            # UI and metadata
            "service_documentation": f"{base_url}/docs/api/oidc/",
            "ui_locales_supported": ["en"],
            "op_policy_uri": f"{base_url}/policy/privacy/",
            "op_tos_uri": f"{base_url}/terms/service/",
            
            # Service metadata
            "claims_parameter_supported": True,
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
            "require_request_uri_registration": False,
        }


class WellKnownConfigurationView(APIView):
    """
    /.well-known/openid-configuration endpoint
    Standard location for OIDC discovery
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        # Redirect to actual provider info
        from django.shortcuts import redirect
        return redirect('oidc-provider-info')