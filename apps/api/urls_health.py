# apps/api/urls_health.py
"""
Health check URLs.
"""

from django.urls import path
from apps.api.views import HealthCheckView

urlpatterns = [
    path('', HealthCheckView.as_view(), name='health-check'),
    path('detailed/', HealthCheckView.as_view(), name='health-check-detailed'),
]