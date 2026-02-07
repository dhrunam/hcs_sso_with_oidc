# apps/api/urls_metrics.py
"""
Metrics URLs.
"""

from django.urls import path
from apps.api.views import MetricsView
from django.contrib.auth.decorators import user_passes_test

urlpatterns = [
    path('', 
         user_passes_test(lambda u: u.is_staff)(MetricsView.as_view()), 
         name='metrics'),
    path('prometheus/', 
         user_passes_test(lambda u: u.is_staff)(MetricsView.as_view()), 
         name='metrics-prometheus'),
]