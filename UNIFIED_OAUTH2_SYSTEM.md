# HCS SSO - Unified OAuth2/JWT Authentication System

## System Overview

This project uses a **unified OAuth2/JWT authentication system** that consolidates all authentication methods into a single standardized flow:

### ✅ Single Token System
- **Type**: JWT with RSA-2048 signature
- **Expiry**: 3600 seconds (1 hour)
- **Refresh**: Automatic via refresh token
- **Standard**: OAuth2 + OpenID Connect (OIDC)

### ✅ Multiple Authentication Methods (All Use Same Token)
1. **Organization Login**: Username/password at `/accounts/login/`
2. **OAuth2 Authorization Code**: For 3rd party apps
3. **OAuth2 Password Grant**: For API clients (Postman, mobile)
4. **Social Providers**: Google, Facebook, Microsoft, GitHub, LinkedIn
5. **OIDC**: Complete OpenID Connect support

### ✅ Unified Entry Point
- **All flows route through**: `/accounts/login/`
- **With integrated social buttons** for provider selection
- **Or direct OAuth2 endpoints** for app-to-app flows

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    User/Client                          │
└─────────────────────────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┬─────────────────┐
        │              │              │                 │
        ▼              ▼              ▼                 ▼
   Browser        Mobile App    REST Client      Social Provider
   (Postman)      (iOS/Android) (Python/Node)    (Google/FB/etc)
        │              │              │                 │
        └──────────────┼──────────────┴─────────────────┘
                       │
                ┌──────▼───────┐
                │ /accounts/   │
                │  login/      │  ◄── Unified Entry Point
                │  (form +     │      with social buttons
                │  social btns)│
                └──────┬───────┘
                       │
          ┌────────────┼────────────┐
          │            │            │
          ▼            ▼            ▼
   Org Form    Social Auth    OAuth2 Flow
   (username)  (Google/FB)    (auth code)
          │            │            │
          └────────────┼────────────┘
                       │
                ┌──────▼────────────┐
                │  /o/token/       │ ◄── Single Token Endpoint
                │  (OAuth2 Provider)│    Returns JWT + Refresh
                └──────┬────────────┘
                       │
                ┌──────▼──────────┐
                │ JWT Access      │
                │ Token (3600s)   │ ◄── Single Token Type
                │ Refresh Token   │    Valid everywhere
                └──────┬──────────┘
                       │
          ┌────────────┼────────────┐
          │            │            │
          ▼            ▼            ▼
      API Calls  User Info   Protected
      (DRF)      (/userinfo) Resources
```

---

## Quick Start for Testing

### Step 1: Create Test User (Once)
```bash
python manage.py shell
>>> from django.contrib.auth.models import User
>>> User.objects.create_user('testuser', 'test@example.com', 'TestPassword123!')
>>> exit()
```

### Step 2: Create OAuth2 App (Once)
1. Go to: `http://localhost:8000/admin/oauth2_provider/application/add/`
2. Create with these settings:
   - **Name**: Postman Client
   - **Client ID**: `postman-client` (or generate)
   - **Client Type**: Confidential or Public
   - **Authorization Grant Type**: Resource owner password-based
   - **Redirect URIs**: `http://localhost:8888/callback`

### Step 3: Get Token (via Password Grant - Easiest for Testing)
```bash
curl -X POST http://localhost:8000/o/token/ \
  -d "grant_type=password&username=testuser&password=TestPassword123!&client_id=postman-client"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "abc123xyz...",
  "id_token": "eyJhbGciOiJSUzI1NiJ9..."
}
```

### Step 4: Use Token in API Calls
```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8000/api/users/profile/
```

---

## Authentication Flows

### 1. Organization Login (Username/Password)

**Flow:**
```
User visits http://localhost:8000/accounts/login/
    ↓
Enters username & password
    ↓
Form validated against Django User model
    ↓
Session created (for browser-based auth)
    ↓
Token generated if OAuth2 app detected
```

**For Postman/API:**
```
POST /o/token/
{
  "grant_type": "password",
  "username": "testuser",
  "password": "TestPassword123!",
  "client_id": "postman-client"
}
```

---

### 2. OAuth2 Authorization Code Flow (3rd Party Apps)

**For web apps needing user consent:**

```
1. Redirect user to:
   /o/authorize/?
     client_id=your_app_id&
     redirect_uri=https://yourapp.com/callback&
     response_type=code&
     scope=openid profile email&
     state=random_123&
     code_challenge=PKCE_CHALLENGE&
     code_challenge_method=S256

2. User sees login form at /accounts/login/

3. User logs in or uses social provider

4. User sees consent screen (if first time)

5. User is redirected to callback with auth code:
   https://yourapp.com/callback?code=abc123&state=random_123

6. Backend exchanges code for token:
   POST /o/token/ {
     "grant_type": "authorization_code",
     "code": "abc123",
     "client_id": "your_app_id",
     "redirect_uri": "https://yourapp.com/callback",
     "code_verifier": "PKCE_VERIFIER"
   }

7. Backend receives token to use on behalf of user
```

**PKCE is Required** for all public clients (mobile apps, SPAs).

---

### 3. Social Provider Login (Google, Facebook, etc.)

**Flow:**
```
User at /accounts/login/ sees:
├─ Organization Form
│  └─ Username/Password fields
└─ Social Buttons
   ├─ Sign in with Google
   ├─ Sign in with Facebook
   ├─ Sign in with Microsoft
   ├─ Sign in with GitHub
   └─ Sign in with LinkedIn

When user clicks social button:
    ↓
Redirects to /social/login/PROVIDER/?next=...
    ↓
Provider's OAuth2 login (Google/Facebook/etc)
    ↓
User authenticates with provider
    ↓
Provider redirects back with user info
    ↓
User profile created/updated if new
    ↓
Session created
    ↓
Token generated for API use
```

**Supported Providers:**
- Google OAuth2 (`google-oauth2`)
- Facebook (`facebook`)
- Microsoft (`microsoft`)
- GitHub (`github`)
- LinkedIn OAuth2 (`linkedin-oauth2`)

---

## API Endpoints

### Authentication

| Endpoint | Method | Purpose | Example |
|----------|--------|---------|---------|
| `/accounts/login/` | GET | Show login form with social buttons | `curl http://localhost:8000/accounts/login/` |
| `/accounts/login/` | POST | Submit org credentials | `curl -X POST http://localhost:8000/accounts/login/ -d "username=test&password=pass"` |
| `/o/authorize/` | GET | OAuth2 authorization endpoint | Browser flow |
| `/o/token/` | POST | Get/refresh token | `curl -X POST http://localhost:8000/o/token/ -d "grant_type=password&..."` |
| `/social/login/PROVIDER/` | GET | Initiate social login | `curl http://localhost:8000/social/login/google-oauth2/` |
| `/.well-known/openid-configuration/` | GET | OIDC discovery | `curl http://localhost:8000/.well-known/openid-configuration/` |

### Protected Resources (Require Token)

| Endpoint | Method | Purpose | Header |
|----------|--------|---------|--------|
| `/api/users/profile/` | GET | Get current user's profile | `Authorization: Bearer TOKEN` |
| `/api/oidc/userinfo/` | GET | Get OIDC userinfo | `Authorization: Bearer TOKEN` |
| `/api/users/` | GET | List users (admin only) | `Authorization: Bearer TOKEN` |

---

## Postman Setup Guide

### Import Collection
1. **Download**: [HCS_SSO_OAuth2_Postman_Collection.json](./HCS_SSO_OAuth2_Postman_Collection.json)
2. **In Postman**: File → Import → Select JSON file

### Quick Test (5 minutes)
1. **Register App**: Visit http://localhost:8000/admin/oauth2_provider/application/add/
   - Name: `Postman`
   - Client ID: `postman-client`
   - Grant: `Resource owner password-based`
   - Redirect: `http://localhost:8888/callback`

2. **Get Token**: Use the "Get Token with Username/Password" request
   - Replace `YOUR_CLIENT_ID` with `postman-client`
   - Click Send
   - Copy `access_token` from response

3. **Use Token**: In "Get User Info" request
   - Replace `YOUR_ACCESS_TOKEN` with token from step 2
   - Click Send
   - See user profile!

---

## Token Structure

### Access Token (JWT)
```
Header: {
  "alg": "RS256",
  "typ": "JWT"
}

Payload: {
  "sub": "testuser",
  "client_id": "postman-client",
  "scopes": ["openid", "profile", "email"],
  "exp": 1699564800,
  "iat": 1699561200,
  "aud": "postman-client"
}

Signature: RSA-2048 signed
```

**Key Points:**
- Signed with RSA-2048 private key
- Expires in 3600 seconds (1 hour)
- Claims include user identity and scopes
- Can be decoded at [jwt.io](https://jwt.io)

### ID Token (JWT)
Returned with OIDC scope, contains:
- User identity claims (sub, email, name)
- Authentication time (auth_time)
- Nonce (for security)

### Refresh Token
- Long-lived token (stored securely)
- Used to get new access tokens
- Revocable at any time

---

## Security Features

### ✅ Token Security
- **Algorithm**: RS256 (RSA-2048)
- **Expiry**: 3600 seconds (1 hour)
- **Storage**: Encrypted in database
- **Rotation**: Refresh tokens rotate on each use

### ✅ Request Security
- **PKCE**: Required for all public clients (mobile, SPAs)
- **CSRF Protection**: Django CSRF middleware
- **HTTPS**: Enforced in production
- **State Parameter**: For OAuth2 CSRF protection

### ✅ Scope Control
- **openid**: OIDC scope
- **profile**: User profile data
- **email**: User email
- **Custom scopes**: Can be added per app

---

## Configuration

### Django Settings (sso/settings.py)

```python
# Unified authentication entry point
LOGIN_URL = '/accounts/login/'
SOCIAL_AUTH_LOGIN_URL = '/accounts/login/'

# OAuth2 Provider Configuration
OAUTH2_PROVIDER = {
    'SCOPES': {
        'read': 'Read access to protected resources',
        'write': 'Write access to protected resources',
        'openid': 'OpenID Connect',
        'profile': 'Access to user profile',
        'email': 'Access to user email',
    },
    'DEFAULT_SCOPES': ['openid', 'profile', 'email'],
    'ACCESS_TOKEN_EXPIRE_SECONDS': 3600,
    'REFRESH_TOKEN_EXPIRE_SECONDS': 3600 * 24 * 7,  # 7 days
    'AUTHORIZATION_CODE_EXPIRE_SECONDS': 600,
    'ROTATE_REFRESH_TOKEN': True,
    'ALLOW_BLANK_REDIRECT_URI': False,
    'REQUEST_APPROVAL_PROMPT': 'auto',
    'PKCE_REQUIRED': True,  # PKCE is mandatory
}

# Social Auth Configuration
AUTHENTICATION_BACKENDS = [
    # OAuth2 backend
    'oauth2_provider.backends.OAuth2Backend',
    # Social auth backends
    'social_core.backends.google.GoogleOAuth2',
    'social_core.backends.facebook.FacebookOAuth2',
    'social_core.backends.microsoft.MicrosoftOAuth2',
    'social_core.backends.github.GithubOAuth2',
    'social_core.backends.linkedin.LinkedInOAuth2Backend',
    # Django default
    'django.contrib.auth.backends.ModelBackend',
]
```

---

## Troubleshooting

### "Invalid Client ID" Error
**Cause**: Client ID doesn't exist or is wrong
**Solution**: 
1. Go to `/admin/oauth2_provider/application/`
2. Verify client ID matches your request
3. Ensure redirect URI is registered

### "Invalid Redirect URI" Error
**Cause**: Redirect URI in request doesn't match registered URI
**Solution**:
1. In admin, check registered redirect URIs
2. Match exactly (case-sensitive, including protocol & port)
3. For testing: register `http://localhost:8888/callback`

### Token Expired
**Cause**: Access token older than 3600 seconds
**Solution**:
1. Use refresh token to get new access token:
   ```bash
   POST /o/token/ {
     "grant_type": "refresh_token",
     "refresh_token": "YOUR_REFRESH_TOKEN",
     "client_id": "postman-client"
   }
   ```
2. Or login again with password grant

### Social Login Not Working
**Cause**: Provider credentials not configured
**Solution**:
1. Check provider OAuth2 app is created (Google Cloud Console, etc)
2. Add credentials to `/admin/socialaccount/socialapp/`
3. Match provider name exactly (google-oauth2, facebook, etc)

### PKCE Required Error
**Cause**: Authorization code flow without PKCE
**Solution**:
1. Always include `code_challenge` and `code_challenge_method`
2. Generate code verifier: random 43-128 char string
3. Calculate challenge: base64url(sha256(verifier))

---

## Migration from Old System

### If Using Old DRF Token (`/api/users/login/`)
The old token endpoint at `/api/users/login/` is removed.

**Migrate to:**
```bash
# Old way (NO LONGER WORKS):
POST /api/users/login/ {
  "username": "testuser",
  "password": "TestPassword123!"
}

# New way (OAuth2 Password Grant):
POST /o/token/ {
  "grant_type": "password",
  "username": "testuser",
  "password": "TestPassword123!",
  "client_id": "your_client_id"
}
```

### Token Format Change
- **Old**: `Token abc123xyz...` (non-expiring)
- **New**: `Bearer eyJhbGciOiJSUzI1NiJ9...` (JWT, 1 hour expiry)

Update your API client headers:
```bash
# Old way
Authorization: Token abc123xyz

# New way
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

---

## Development Tips

### Create Test User
```bash
python manage.py shell
>>> from django.contrib.auth.models import User
>>> User.objects.create_user('testuser', 'test@example.com', 'TestPassword123!')
```

### Create OAuth2 App Programmatically
```bash
python manage.py shell
>>> from oauth2_provider.models import Application
>>> from django.contrib.auth.models import User
>>> user = User.objects.first()
>>> Application.objects.create(
...   name='Test App',
...   client_id='test-client',
...   user=user,
...   client_type='public',
...   authorization_grant_type='password',
...   redirect_uris='http://localhost:8888/callback'
... )
```

### Decode JWT Token
```bash
# At https://jwt.io or command line:
python -c "import jwt; print(jwt.decode('TOKEN_HERE', options={'verify_signature': False}))"
```

### Test in Browser
1. `http://localhost:8000/accounts/login/` - Organization login
2. Social buttons available on same page
3. After login, redirects to dashboard or next page

---

## Support

For issues or questions:
1. Check [SECURITY_FIXES.md](./SECURITY_FIXES.md) for known issues
2. Check [IMPLEMENTATION_READINESS.md](./IMPLEMENTATION_READINESS.md) for status
3. Review auth logs: `logs/` directory
4. Check Django debug toolbar: `?__debug__=1`

---

## References

- [OAuth2 Specification](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE](https://tools.ietf.org/html/rfc7636)
- [JWT](https://tools.ietf.org/html/rfc7519)
- [django-oauth-toolkit](https://django-oauth-toolkit.readthedocs.io/)
- [django-social-auth](https://python-social-auth.readthedocs.io/)
