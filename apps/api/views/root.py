from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny


class APIRootView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        base_url = request.build_absolute_uri('/').rstrip('/')

        api_info = {
            'name': 'Organization SSO API',
            'version': getattr(settings, 'API_VERSION', '1.0.0'),
            'description': 'Single Sign-On and Identity Management API',
            'documentation': {
                'openapi': f'{base_url}/api/docs/',
                'redoc': f'{base_url}/api/redoc/',
                'oidc_discovery': f'{base_url}/.well-known/openid-configuration',
            },
            'endpoints': {
                'authentication': {
                    'login': f'{base_url}/api/users/login/',
                    'logout': f'{base_url}/api/users/logout/',
                    'register': f'{base_url}/api/users/register/',
                    'profile': f'{base_url}/api/users/profile/',
                },
                'oauth2': {
                    'authorize': f'{base_url}/o/authorize/',
                    'token': f'{base_url}/o/token/',
                    'revoke': f'{base_url}/o/revoke/',
                    'introspect': f'{base_url}/o/introspect/',
                },
                'oidc': {
                    'userinfo': f'{base_url}/api/oidc/userinfo/',
                    'jwks': f'{base_url}/api/oidc/jwks/',
                    'client_registration': f'{base_url}/api/clients/register/',
                },
                'social': {
                    'providers': f'{base_url}/api/social/providers/',
                    'connections': f'{base_url}/api/social/connections/',
                },
                'system': {
                    'health': f'{base_url}/api/health/',
                    'metrics': f'{base_url}/api/metrics/',
                    'info': f'{base_url}/api/system/info/',
                },
            },
            'authentication_methods': ['Bearer Token', 'Session', 'OAuth2', 'OpenID Connect'],
            'contact': {
                'email': getattr(settings, 'API_CONTACT_EMAIL', 'api@example.com'),
                'documentation': getattr(settings, 'API_DOCS_URL', ''),
            },
        }

        return Response(api_info)
