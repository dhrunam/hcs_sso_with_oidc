"""
URL configuration for SSO (Single Sign-On) project.
"""

from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),
    
    # OAuth2/OIDC
    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    
    # API Endpoints
    path('api/', include('apps.api.urls', namespace='api')),
    path('api/users/', include('apps.users.urls', namespace='users')),
    path('api/oidc/', include('apps.oidc.urls', namespace='oidc')),
    path('api/social/', include('apps.social.urls', namespace='social')),
   
    
    # Social Auth (only if social_django is installed)
    *([path('social/', include('social_django.urls', namespace='social_django'))] 
      if 'social_django' in settings.INSTALLED_APPS else []),
    
    # Frontend Pages
    # path('', TemplateView.as_view(template_name='index.html'), name='home'),
    # path('login/', TemplateView.as_view(template_name='login.html'), name='login'),
    # path('profile/', TemplateView.as_view(template_name='profile.html'), name='profile'),
    
    # OIDC Discovery
    path('.well-known/openid-configuration/', 
         include('apps.oidc.urls')),  # No namespace here, it's included above
]

# Debug toolbar (development only)
if settings.DEBUG:
    urlpatterns += [
        path('__debug__/', include('debug_toolbar.urls')),
    ]
    
    # Serve static/media files in development
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Fix for social_core import issue in apps.py
# Add this to your apps/social/apps.py to handle missing social_core gracefully