from django.urls import path, include

# Namespacing required when included with `namespace=` in project urls
app_name = 'oidc'
from .views.discovery import (
    JWKSDocumentView,
    OIDCProviderInfoView,
    WellKnownConfigurationView
)
from .views.token import (
    OIDCUserInfoView,
    TokenIntrospectionView,
    TokenRevocationView,
    SessionManagementView
)
from .views.client import ClientRegistrationView

urlpatterns = [
    # Discovery endpoints
    path('jwks/', JWKSDocumentView.as_view(), name='oidc-jwks'),
    path('provider-info/', OIDCProviderInfoView.as_view(), name='oidc-provider-info'),
    path('.well-known/openid-configuration/', 
         WellKnownConfigurationView.as_view(), 
         name='oidc-well-known'),
    
    # Token management endpoints
    path('userinfo/', OIDCUserInfoView.as_view(), name='oidc-userinfo'),
    path('introspect/', TokenIntrospectionView.as_view(), name='oidc-introspect'),
    path('revoke/', TokenRevocationView.as_view(), name='oidc-revoke'),
    path('sessions/', SessionManagementView.as_view(), name='oidc-sessions'),
    path('sessions/<int:session_id>/', 
         SessionManagementView.as_view(), 
         name='oidc-session-detail'),
    
    # Client registration
    path('register/', ClientRegistrationView.as_view(), name='oidc-register'),
    
    # Include Django OAuth Toolkit URLs
    path('', include('oauth2_provider.urls', namespace='oauth2_provider')),
]