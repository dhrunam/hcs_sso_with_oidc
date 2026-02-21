from rest_framework.permissions import BasePermission, SAFE_METHODS
from oauth2_provider.models import AccessToken
from django.utils import timezone

class IsOAuth2Authenticated(BasePermission):
    """
    Permission class that checks for valid OAuth2 token
    instead of session authentication
    """
    def has_permission(self, request, view):
        # Check for bearer token in Authorization header
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return False
        
        token_string = auth_header.split(' ')[1]
        
        try:
            token = AccessToken.objects.get(
                token=token_string,
                expires__gt=timezone.now()
            )
            request.user = token.user
            request.access_token = token
            return True
        except AccessToken.DoesNotExist:
            return False


class HasScope(BasePermission):
    """
    Permission class that checks for specific OAuth2 scopes
    """
    def __init__(self, required_scopes):
        self.required_scopes = required_scopes if isinstance(required_scopes, list) else [required_scopes]
    
    def has_permission(self, request, view):
        if not hasattr(request, 'access_token'):
            return False
        
        token_scopes = set(request.access_token.scope.split())
        required_scopes = set(self.required_scopes)
        
        return required_scopes.issubset(token_scopes)


class IsClientAuthenticated(BasePermission):
    """
    Permission class for client authentication (client credentials)
    Supports both HTTP Basic Auth and POST client_id/client_secret
    
    RFC 6750: Bearer Token Usage
    RFC 6749: OAuth 2.0 Authorization Framework (Client Authentication)
    """
    def has_permission(self, request, view):
        from oauth2_provider.models import Application
        import base64
        import logging
        
        logger = logging.getLogger(__name__)
        
        client_id = None
        client_secret = None
        
        # Method 1: HTTP Basic Authentication (preferred)
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Basic '):
            try:
                encoded_credentials = auth_header.split(' ')[1]
                decoded = base64.b64decode(encoded_credentials).decode('utf-8')
                client_id, client_secret = decoded.split(':', 1)
            except (ValueError, IndexError, UnicodeDecodeError):
                logger.warning(f"Invalid Basic Auth header from {request.META.get('REMOTE_ADDR')}")
                return False
        
        # Method 2: POST body client credentials
        if not client_id:
            client_id = request.data.get('client_id') if hasattr(request, 'data') else request.POST.get('client_id')
            client_secret = request.data.get('client_secret') if hasattr(request, 'data') else request.POST.get('client_secret')
        
        if not client_id or not client_secret:
            logger.warning(f"Missing client credentials from {request.META.get('REMOTE_ADDR')}")
            return False
        
        # Verify client exists and credentials match
        try:
            app = Application.objects.get(client_id=client_id)
            
            # Verify secret
            if app.client_secret != client_secret:
                logger.warning(f"Invalid client secret for client_id {client_id} from {request.META.get('REMOTE_ADDR')}")
                return False
            
            # Attach application to request for later use
            request.client_app = app
            logger.info(f"Client {client_id} authenticated from {request.META.get('REMOTE_ADDR')}")
            return True
            
        except Application.DoesNotExist:
            logger.warning(f"Unknown client_id {client_id} from {request.META.get('REMOTE_ADDR')}")
            return False