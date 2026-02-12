# SSO OAuth 2.0 / OpenID Connect Flow Guide

## Overview

This document explains the configured SSO authentication flow for your High Court of Sikkim (HCS) SSO project. When an application requests authorization via OAuth 2.0, users are guided through a multi-step authentication process where they can choose their preferred login method.

---

## Complete Authentication Flow

### 1. Application Initiates OAuth 2.0 Request

An external application (client) redirects users to the authorization endpoint:

```
GET http://localhost:8000/o/authorize/?
    client_id=<client_id>&
    redirect_uri=<redirect_uri>&
    response_type=code&
    scope=openid+profile+email&
    state=<random_state>&
    code_challenge=<pkce_challenge>
```

### 2. OAuth2 Provider Checks Authentication

The django-oauth-toolkit middleware checks if the user is authenticated:

- **If authenticated**: Proceeds to authorization scope approval
- **If NOT authenticated**: Redirects to `LOGIN_URL` (set to `/login/` in settings)

### 3. User Arrives at /login/ - Choose Authentication Method

URL: `http://localhost:8000/login/`

The user sees a login method selection page with these options:

#### Option A: Organization (HCS) Account
- **Button**: "HCS Account" with organization building icon
- **Redirects to**: `http://localhost:8000/accounts/login/`
- **Purpose**: For users with HCS employee credentials

#### Option B: Social Login
Users can choose from:
- Google: `/social/login/google-oauth2/`
- Facebook: `/social/login/facebook/`
- Microsoft: `/social/login/microsoft-graph/`
- GitHub: `/social/login/github/`
- LinkedIn: `/social/login/linkedin-oauth2/`

---

## Organization (HCS) Account Login Flow

### Step 3A: User Enters Organization Credentials

URL: `http://localhost:8000/accounts/login/`

**View**: `OrganizationLoginView` (in `apps/core/views.py`)

**Form Fields**:
- Username (email or username)
- Password
- Remember me (checkbox)

**Template**: `templates/registration/login.html`

### Step 3B: Credential Validation

Django's built-in authentication backend validates:
- Username exists in `django_auth_user` table
- Password matches (using bcrypt/argon2)
- Account is active (`is_active=True`)

### Step 3C: Successful Login

Upon successful authentication:

1. Django session is created
2. User is logged in (`login(request, user)`)
3. If `next` parameter exists (from OAuth2 flow), redirects back to OAuth2
4. Otherwise, redirects to homepage (`/`)

**Important**: The `next` parameter is automatically preserved and passed through the form, enabling seamless redirect back to the OAuth2 authorization flow.

### Step 3D: Back to OAuth2 Authorization

After login, the user is redirected back to:

```
GET http://localhost:8000/o/authorize/?
    client_id=<client_id>&
    ...
    (same parameters as original request)
```

Now the user IS authenticated, so the OAuth2 provider shows the **scope consent screen** asking:
- "Do you want to allow this application to access your profile, email, etc.?"

### Step 4: User Grants/Denies Permission

- **Grant**: Authorization code is generated and user is redirected to `redirect_uri` with the code
- **Deny**: User is redirected to `redirect_uri` with an error parameter

---

## Social Login Flow

### Step 3B (Alternative): Social Provider Login

**For social providers** (Google, Facebook, etc.):

```
Social Login Button → /social/login/<provider>/
    ↓
Provider's login page (Google, Facebook, etc.)
    ↓
Provider authenticates user
    ↓
Provider redirects to /social/complete/<provider>/
    ↓
django-social-auth creates/updates user
    ↓
Redirects based on SOCIAL_AUTH_LOGIN_REDIRECT_URL setting
```

---

## Configuration Files

### 1. **sso/settings.py** - Authentication Settings

```python
# Login URL configuration
LOGIN_URL = '/login/'  # Where to redirect when authorization is required
LOGIN_REDIRECT_URL = '/'  # After successful login
LOGOUT_REDIRECT_URL = '/'  # After logout

# Social auth settings
SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/'
SOCIAL_AUTH_LOGIN_URL = '/login/'
SOCIAL_AUTH_POSTGRES_JSONFIELD = True

# OIDC/OAuth2 Settings
OAUTH2_PROVIDER = {
    'OIDC_ENABLED': True,
    'PKCE_REQUIRED': True,
    'SCOPES': {
        'openid': 'OpenID Connect',
        'profile': 'User profile',
        'email': 'Email address',
        'offline_access': 'Offline access',
    },
}
```

### 2. **sso/urls.py** - URL Routing

```python
# Frontend Pages
path('', TemplateView.as_view(template_name='index.html'), name='home'),
# Main login page - user chooses authentication method
path('login/', TemplateView.as_view(template_name='login.html'), name='login'),
# Organization account login - handles username/password
path('accounts/login/', OrganizationLoginView.as_view(), name='organization_login'),

# OAuth2/OIDC
path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
path('social/', include('social_django.urls', namespace='social_django')),
```

### 3. **apps/core/views.py** - Organization Login View

```python
class OrganizationLoginView(DjangoLoginView):
    template_name = 'registration/login.html'
    form_class = AuthenticationForm
    
    def form_valid(self, form):
        user = form.get_user()
        login(self.request, user)
        
        # Preserve 'next' parameter for OAuth2 redirect
        next_url = self.request.GET.get('next') or self.request.POST.get('next')
        if next_url:
            return HttpResponseRedirect(next_url)
        
        return super().form_valid(form)
```

---

## Step-by-Step Testing

### Test Case 1: OAuth2 Authorization with Organization Login

```bash
# Start the development server
python manage.py runserver

# Register a test OAuth2 application at http://localhost:8000/o/applications/
# Note the client_id

# Create a test user for organization login
python manage.py createsuperuser
# username: testuser
# password: TestPassword123!

# Simulate OAuth2 authorization request
# Visit: http://localhost:8000/o/authorize/?client_id=<YOUR_CLIENT_ID>&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid+profile+email
```

### Expected Flow:

1. ✅ Redirects to `/login/` (user not authenticated)
2. ✅ User sees login options (HCS Account, Google, Facebook, etc.)
3. ✅ User clicks "HCS Account"
4. ✅ Directed to `/accounts/login/`
5. ✅ User enters credentials (testuser / TestPassword123!)
6. ✅ On success, redirected back to OAuth2 authorization
7. ✅ Shows scope consent screen
8. ✅ User grants permission
9. ✅ Authorization code generated
10. ✅ Redirected to `redirect_uri?code=<auth_code>&state=<state>`

---

## Key Features

### ✅ PKCE Support
- Protects against authorization code interception
- Required for public clients (SPAs, mobile apps)
- Automatically handled by django-oauth-toolkit

### ✅ JWT ID Tokens
- Contains user claims (sub, name, email, etc.)
- Signed with RSA-2048 private key
- Can be verified using JWKS endpoint: `/.well-known/jwks.json`

### ✅ OpenID Connect Discovery
- Endpoint: `/.well-known/openid-configuration/`
- Exposes authorization, token, userinfo, and jwks endpoints
- Clients can automatically discover configuration

### ✅ Multiple Authentication Methods
- Organization credentials (username/password)
- Social providers (Google, Facebook, Microsoft, GitHub, LinkedIn)
- Seamless switching between methods

### ✅ Security
- CSRF protection on all forms
- Secure session cookies (httponly, secure in production)
- Password hashing with argon2/bcrypt
- Rate limiting on introspection endpoint
- State parameter validation

---

## Troubleshooting

### Problem: Redirected to /login/ instead of /accounts/login/
**Solution**: Ensure `LOGIN_URL = '/login/'` in settings and user isn't already authenticated.

### Problem: OAuth2 redirect loop
**Solution**: Check that `next` parameter is correctly preserved in the form. View passes it via context and template includes it as hidden input.

### Problem: User not redirected after login
**Solution**: Verify `next` parameter is being passed. Check logs for any redirect errors.

### Problem: PKCE validation errors
**Solution**: Ensure client is sending valid `code_challenge` and `code_verifier` on token request. PKCE is required in settings.

### Problem: Social login not working
**Solution**: 
- Check provider credentials (GOOGLE_CLIENT_ID, FACEBOOK_APP_ID, etc.) in `.env`
- Verify `social_django` is in INSTALLED_APPS
- Check redirect URIs are configured in provider dashboards

---

## User Creation for Organization Login

### Option 1: Django Admin

```
Visit: http://localhost:8000/admin/
Login with superuser
Navigate: Authentication and Authorization > Users > Add User
```

### Option 2: Management Command

```bash
python manage.py createsuperuser
# or
python manage.py shell
>>> from django.contrib.auth.models import User
>>> User.objects.create_user(username='john', email='john@hcs.gov', password='SecurePass123!')
```

### Option 3: REST API (if available)

```bash
curl -X POST http://localhost:8000/api/users/register/ \
  -H "Content-Type: application/json" \
  -d '{"username":"john","email":"john@hcs.gov","password":"SecurePass123!"}'
```

---

## Production Deployment Checklist

- [ ] Set `DEBUG = False`
- [ ] Set secure `SECRET_KEY`
- [ ] Enable HTTPS (`SECURE_SSL_REDIRECT = True`)
- [ ] Configure CORS properly (`CORS_ALLOWED_ORIGINS`)
- [ ] Set `ALLOWED_HOSTS` to your domain
- [ ] Enable HSTS (`SECURE_HSTS_SECONDS`)
- [ ] Configure email backend for password reset
- [ ] Set up database backups
- [ ] Enable logging and monitoring
- [ ] Configure provider credentials securely via environment variables
- [ ] Test all authentication flows thoroughly

---

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/login/` | GET | Login method selection page |
| `/accounts/login/` | GET, POST | Organization credential login |
| `/o/authorize/` | GET | OAuth2 authorization endpoint |
| `/o/token/` | POST | OAuth2 token endpoint |
| `/.well-known/openid-configuration/` | GET | OIDC discovery endpoint |
| `/api/oidc/jwks/` | GET | JSON Web Key Set |
| `/api/oidc/userinfo/` | GET, POST | User information endpoint |
| `/social/login/<provider>/` | GET | Social login initiation |
| `/social/complete/<provider>/` | GET | Social provider callback |

---

## References

- [OAuth 2.0 Authorization Code Flow](https://tools.ietf.org/html/rfc6749#section-1.3.1)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE (RFC 7636)](https://tools.ietf.org/html/rfc7636)
- [django-oauth-toolkit Documentation](https://django-oauth-toolkit.readthedocs.io/)
- [django-social-auth Documentation](https://python-social-auth.readthedocs.io/)

---

## Next Steps

1. **Create test users** for organization login
2. **Register OAuth2 applications** to test the flow
3. **Configure social provider credentials** (.env file)
4. **Test complete flow** from OAuth2 initiation to token receipt
5. **Monitor logs** for authentication events
6. **Set up monitoring/alerting** for failed login attempts

