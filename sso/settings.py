# sso/settings.py

import os
from pathlib import Path
from dotenv import load_dotenv
import json

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = os.getenv('SECRET_KEY', 'fallback-secret-key')
DEBUG = os.getenv('DEBUG', 'False') == 'True'

ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'sso.diseso.com']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    
    # Third-party apps
    'rest_framework',
    'oauth2_provider',
    'corsheaders',
    "social_django",
    
   # Documentation
    'drf_yasg',  # or 'drf_spectacular'
    
    # Development tools (only enable in DEBUG)
    *([] if not DEBUG else ['debug_toolbar', 'silk']),
    
    # Local apps
   'apps.core',            # Models
    'apps.users',           # User management APIs
    'apps.oidc',            # YOUR OIDC provider
    'apps.social',          # Social auth (to external providers)
    'apps.api',             # General APIs
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    *(['debug_toolbar.middleware.DebugToolbarMiddleware'] if DEBUG else []),
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    *(['silk.middleware.SilkyMiddleware'] if DEBUG else []),
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'oauth2_provider.middleware.OAuth2TokenMiddleware',
]

ROOT_URLCONF = 'sso.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                
            ],
        },
    },
]

WSGI_APPLICATION = 'sso.wsgi.application'

# Database
DATABASES = {
    # 'default': {
    #     'ENGINE': 'django.db.backends.sqlite3',
    #     'NAME': BASE_DIR / 'db.sqlite3',
    # }

    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('POSTGRES_DB', 'hcs_sso_oidc_db'),
        'USER': os.getenv('POSTGRES_USER', 'postgres'),
        'PASSWORD': os.getenv('POSTGRES_PASSWORD', 'postgres'),
        'HOST': os.getenv('POSTGRES_HOST', 'localhost'),
        'PORT': os.getenv('POSTGRES_PORT', '5435'), 
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ============ AUTHENTICATION CONFIGURATION ============

SITE_ID = 1

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'social_core.backends.google.GoogleOAuth2',
    'social_core.backends.facebook.FacebookOAuth2',
    'social_core.backends.microsoft.MicrosoftOAuth2',
    'social_core.backends.github.GithubOAuth2',
    'social_core.backends.linkedin.LinkedinOAuth2',
    'social_core.backends.open_id_connect.OpenIdConnectAuth',  # For generic OIDC
]

# Social auth settings
SOCIAL_AUTH_POSTGRES_JSONFIELD = True  # If using PostgreSQL
SOCIAL_AUTH_URL_NAMESPACE = 'social'
SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/'
SOCIAL_AUTH_LOGIN_ERROR_URL = '/login-error/'
SOCIAL_AUTH_LOGOUT_REDIRECT_URL = '/'
SOCIAL_AUTH_NEW_USER_REDIRECT_URL = '/profile/'
SOCIAL_AUTH_LOGIN_URL = '/login/'



# Exact origins only (optional)
CORS_ALLOWED_ORIGINS = [
    "http://localhost:4200",
]

# REGEX-based origins (this is what you need)
CORS_ALLOWED_ORIGIN_REGEXES = [
    r"^http://localhost:\d+$",
    r"^https://.*\.diseso\.com$",
    r"^https://diseso\.com$",
]

CORS_ALLOW_CREDENTIALS = True
CORS_EXPOSE_HEADERS = ['Content-Type', 'Authorization']

# ============ OAUTH2 & OIDC CONFIGURATION ============

# Generate RSA keys for OIDC
def generate_rsa_key():
    """Generate RSA key if not exists"""
    key_path = BASE_DIR / 'oidc_private_key.pem'
    if not key_path.exists():
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open(key_path, 'wb') as f:
            f.write(private_pem)
        
        # Also generate public key
        public_key = key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(BASE_DIR / 'oidc_public_key.pem', 'wb') as f:
            f.write(public_pem)
    
    return key_path.read_text()

OIDC_PRIVATE_KEY = generate_rsa_key()

# OAuth2 Provider Configuration
OAUTH2_PROVIDER = {
    # OIDC Settings
    'OIDC_ENABLED': True,
    'OIDC_RSA_PRIVATE_KEY': OIDC_PRIVATE_KEY,
    'OIDC_ISS_ENDPOINT': 'http://localhost:8000/o',
    
    # Token Settings
    'ACCESS_TOKEN_EXPIRE_SECONDS': 3600,  # 1 hour
    'REFRESH_TOKEN_EXPIRE_SECONDS': 86400,  # 1 day
    'REFRESH_TOKEN_GRACE_PERIOD_SECONDS': 3600,
    'ID_TOKEN_EXPIRE_SECONDS': 3600,
    
    # PKCE for SPAs
    'PKCE_REQUIRED': True,
    
    # Scopes
    'SCOPES': {
        'openid': 'OpenID Connect',
        'profile': 'User profile',
        'email': 'Email address',
        'read': 'Read access',
        'write': 'Write access',
        'offline_access': 'Offline access',
    },
    
    # Claims
    'OIDC_CLAIMS_ENABLED': True,
    'OAUTH2_VALIDATOR_CLASS': 'apps.oidc.validators.CustomOAuth2Validator',
    
    # Application settings
    'APPLICATION_MODEL': 'oauth2_provider.Application',
    'ACCESS_TOKEN_MODEL': 'oauth2_provider.AccessToken',
    'REFRESH_TOKEN_MODEL': 'oauth2_provider.RefreshToken',
    
    # PKCE methods
    'PKCE_METHODS': ['S256', 'plain'],
}

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'oauth2_provider.contrib.rest_framework.OAuth2Authentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ),
}

# ============ SOCIAL PROVIDER CONFIGURATION ============

# Provider-specific settings
SOCIAL_AUTH_GOOGLE_OIDC_ENABLED = True
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = os.getenv('GOOGLE_CLIENT_ID')
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE = [
    'openid',
    'profile',
    'email',
]
SOCIAL_AUTH_GOOGLE_OAUTH2_AUTH_EXTRA_ARGUMENTS = {
    'access_type': 'online',
    'prompt': 'select_account',
}

SOCIAL_AUTH_FACEBOOK_KEY = os.getenv('FACEBOOK_CLIENT_ID')
SOCIAL_AUTH_FACEBOOK_SECRET = os.getenv('FACEBOOK_CLIENT_SECRET')
SOCIAL_AUTH_FACEBOOK_SCOPE = ['email', 'public_profile']
SOCIAL_AUTH_FACEBOOK_PROFILE_EXTRA_PARAMS = {
    'fields': 'id,name,email,first_name,last_name,picture'
}
SOCIAL_AUTH_FACEBOOK_API_VERSION = '13.0'

SOCIAL_AUTH_MICROSOFT_GRAPH_KEY = os.getenv('MICROSOFT_CLIENT_ID')
SOCIAL_AUTH_MICROSOFT_GRAPH_SECRET = os.getenv('MICROSOFT_CLIENT_SECRET')
SOCIAL_AUTH_MICROSOFT_GRAPH_TENANT = 'common'
SOCIAL_AUTH_MICROSOFT_GRAPH_SCOPE = ['User.Read']

SOCIAL_AUTH_GITHUB_KEY = os.getenv('GITHUB_CLIENT_ID')
SOCIAL_AUTH_GITHUB_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
SOCIAL_AUTH_GITHUB_SCOPE = ['user:email', 'read:user']

SOCIAL_AUTH_LINKEDIN_OAUTH2_KEY = os.getenv('LINKEDIN_CLIENT_ID')
SOCIAL_AUTH_LINKEDIN_OAUTH2_SECRET = os.getenv('LINKEDIN_CLIENT_SECRET')
SOCIAL_AUTH_LINKEDIN_OAUTH2_SCOPE = ['r_liteprofile', 'r_emailaddress']
SOCIAL_AUTH_LINKEDIN_OAUTH2_FIELD_SELECTORS = [
    'id',
    'firstName',
    'lastName',
    'profilePicture(displayImage~:playableStreams)',
]

# For custom OIDC providers (like your organizational SSO)
SOCIAL_AUTH_OIDC_ENABLED = True
SOCIAL_AUTH_OIDC_KEY = os.getenv('OIDC_CLIENT_ID')
SOCIAL_AUTH_OIDC_SECRET = os.getenv('OIDC_CLIENT_SECRET')
SOCIAL_AUTH_OIDC_DOMAIN = os.getenv('OIDC_URL') # Example
SOCIAL_AUTH_OIDC_OIDC_ENDPOINT = f'{SOCIAL_AUTH_OIDC_DOMAIN}/.well-known/openid-configuration'

# Security settings
SOCIAL_AUTH_REDIRECT_IS_HTTPS = not DEBUG
SOCIAL_AUTH_SANITIZE_REDIRECTS = True
SOCIAL_AUTH_PROTECTED_USER_FIELDS = ['email', 'username']

# ============ PRODUCTION SECURITY SETTINGS ============
# These settings should be enabled in production (DEBUG=False)
# Verify they are appropriate for your deployment architecture

# HTTPS/TLS Settings
if not DEBUG:
    # Enable HTTPS redirection
    SECURE_SSL_REDIRECT = True
    
    # HSTS (HTTP Strict Transport Security)
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    
    # Cookie Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_SECURE = True
    
    # Content Security
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_BROWSER_XSS_FILTER = True
    X_FRAME_OPTIONS = 'DENY'
    
    # Referrer Policy
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
else:
    # Development settings
    X_FRAME_OPTIONS = 'SAMEORIGIN'

# Ensure SECRET_KEY is set in production
if DEBUG is False and SECRET_KEY == 'fallback-secret-key':
    raise ValueError(
        "SECRET_KEY must be set via environment variable in production. "
        "Set SECRET_KEY env var to a secure random string."
    )

# Ensure ALLOWED_HOSTS is properly configured
if DEBUG is False and ALLOWED_HOSTS == ['localhost', '127.0.0.1', 'sso.yourorg.com']:
    raise ValueError(
        "ALLOWED_HOSTS must be properly configured for your domain in production. "
        "Update ALLOWED_HOSTS or set via environment variable."
    )

# Session and CSRF configuration
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
CSRF_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_SAMESITE = 'Strict'

# Logging for security events
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'django.log',
            'maxBytes': 1024 * 1024 * 10,  # 10MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'security': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'security.log',
            'maxBytes': 1024 * 1024 * 10,  # 10MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
        'django.security': {
            'handlers': ['security', 'console'],
            'level': 'WARNING',
        },
        'apps.oidc': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
        'apps.social': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
    },
}

# Create logs directory if it doesn't exist
import logging.handlers
logs_dir = BASE_DIR / 'logs'
logs_dir.mkdir(exist_ok=True)