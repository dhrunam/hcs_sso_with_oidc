from rest_framework.throttling import AnonRateThrottle, UserRateThrottle

class JWKSThrottle(AnonRateThrottle):
    """Throttle for JWKS endpoint"""
    rate = '100/day'
    scope = 'jwks'
    
    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)
        
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }


class IntrospectionThrottle(UserRateThrottle):
    """Throttle for introspection endpoint"""
    rate = '60/minute'
    scope = 'introspection'
    
    def get_cache_key(self, request, view):
        # Use client_id for throttling if available
        client_id = request.data.get('client_id') or request.query_params.get('client_id')
        if client_id:
            ident = client_id
        elif request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)
        
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }


class RegistrationThrottle(UserRateThrottle):
    """Throttle for client registration endpoint"""
    rate = '10/day'
    scope = 'registration'
    
    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)
        
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }