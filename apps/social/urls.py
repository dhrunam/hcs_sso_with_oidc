# apps/social/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    SocialLoginInitiateView,
    SocialCallbackView,
    SocialConnectionsViewSet,
    SocialProvidersView,
    SocialLoginHistoryView,
    admin_social_stats,
)

router = DefaultRouter()
router.register(r'connections', SocialConnectionsViewSet, basename='social-connections')
app_name = 'social'
urlpatterns = [
    # Social authentication flow
    path('login/<str:provider>/', SocialLoginInitiateView.as_view(), name='social-login-initiate'),
    path('callback/<str:provider>/', SocialCallbackView.as_view(), name='social-login-callback'),
    
    # Social providers
    path('providers/', SocialProvidersView.as_view(), name='social-providers'),
    
    # Login history
    path('history/', SocialLoginHistoryView.as_view(), name='social-login-history'),
    
    # Admin endpoints
    path('admin/stats/', admin_social_stats, name='admin-social-stats'),
    
    # Include ViewSet URLs
    path('', include(router.urls)),
]