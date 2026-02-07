# apps/api/urls.py
from django.urls import path

# Namespacing required when included with `namespace=` in project urls
app_name = 'api'
from .views import (
    APIRootView,
    HealthCheckView,
    SystemInfoView,
    MetricsView,
    ClientRegistrationView,
    ClientManagementView,
    robots_txt,
    security_txt,
)

urlpatterns = [
    # API Root
    path('', APIRootView.as_view(), name='api-root'),
    
    # Health & System
    path('health/', HealthCheckView.as_view(), name='health-check'),
    path('system/info/', SystemInfoView.as_view(), name='system-info'),
    path('metrics/', MetricsView.as_view(), name='metrics'),
    
    # Client Management
    path('clients/register/', ClientRegistrationView.as_view(), name='client-register'),
    path('clients/', ClientManagementView.as_view(), name='client-list'),
    path('clients/<str:client_id>/', ClientManagementView.as_view(), name='client-detail'),
    
    # Well-known endpoints
    path('robots.txt', robots_txt, name='robots-txt'),
    path('.well-known/security.txt', security_txt, name='security-txt'),
]