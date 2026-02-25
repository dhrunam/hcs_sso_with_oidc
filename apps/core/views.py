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


