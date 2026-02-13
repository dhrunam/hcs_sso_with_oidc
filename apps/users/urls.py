# apps/users/urls.py
from django.urls import path, include

# Namespacing required when included with `namespace=` in project urls
app_name = 'users'
from rest_framework.routers import DefaultRouter
from .views import (
    UserRegistrationView,
    UserRegistrationFormView,
    UserProfileView,
    PasswordChangeView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    UserLogoutView,
    LoginOptionsView,
    AdminUserViewSet,
    AdminUserStatsView,
    AdminUserSearchView,
    PublicUserInfoView,
    VerifyEmailView,
    health_check,
)

router = DefaultRouter()
router.register(r'admin/users', AdminUserViewSet, basename='admin-users')

urlpatterns = [
    # Authentication via OAuth2 /o/token/ endpoint (not REST token)
    # DELETE: DRF token endpoint removed - use OAuth2 instead
    # Users should authenticate via /o/token/ with grant_type=password
    
    # User operations
    path('logout/', UserLogoutView.as_view(), name='user-logout'),
    
    # Registration & Profile
    path('register-form/', UserRegistrationFormView.as_view(), name='user-register-form'),  # Template-based form
    path('register/', UserRegistrationView.as_view(), name='user-register'),  # REST API endpoint
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    
    # Password management
    path('password/change/', PasswordChangeView.as_view(), name='password-change'),
    path('password/reset/request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    
    # Email verification
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    
    # Login options
    path('login-options/', LoginOptionsView.as_view(), name='login-options'),
    
    # Public user info
    path('<int:user_id>/public/', PublicUserInfoView.as_view(), name='public-user-info'),
    
    # Health check
    path('health/', health_check, name='health-check'),
    
    # Admin endpoints
    path('admin/users/stats/', AdminUserStatsView.as_view(), name='admin-user-stats'),
    path('admin/users/search/', AdminUserSearchView.as_view(), name='admin-user-search'),
    
    # Include router URLs
    path('', include(router.urls)),
]