"""
Core authentication views for SSO.
"""
from django.contrib.auth import authenticate, login
from django.contrib.auth.views import LoginView as DjangoLoginView
from django.views.generic import FormView
from django.urls import reverse_lazy
from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm
from django.http import HttpResponseRedirect
import logging

logger = logging.getLogger(__name__)


class OrganizationLoginView(DjangoLoginView):
    """
    Organization account login view.
    Handles username/password authentication for organization SSO.
    
    Flow:
    1. User arrives at /o/authorize/ (OAuth2 endpoint)
    2. OAuth2 provider checks if user is authenticated
    3. If not, redirects to LOGIN_URL (/login/) in settings
    4. User chooses "HCS Account" -> comes to /accounts/login/
    5. User enters credentials
    6. On success, redirects back to OAuth2 authorization
    """
    template_name = 'registration/login.html'
    form_class = AuthenticationForm
    success_url = reverse_lazy('home')
    
    def form_valid(self, form):
        """
        Log the user in and handle OAuth2 redirect.
        If 'next' parameter is present, redirect there after login.
        """
        user = form.get_user()
        login(self.request, user)
        logger.info(f"Organization login successful for user: {user.username}")
        
        # Get the 'next' parameter from GET or POST
        next_url = self.request.GET.get('next') or self.request.POST.get('next')
        
        # If coming from OAuth2 /o/authorize/, 'next' will be the authorization URL
        if next_url:
            return HttpResponseRedirect(next_url)
        
        # Fall back to success_url
        return super().form_valid(form)
    
    def get_context_data(self, **kwargs):
        """Add extra context for the template."""
        context = super().get_context_data(**kwargs)
        context['login_method'] = 'organization'
        context['next'] = self.request.GET.get('next') or self.request.POST.get('next')
        return context
