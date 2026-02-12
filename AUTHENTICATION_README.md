# HCS SSO - Unified OAuth2/JWT Authentication System

## 🎯 What's New

Your authentication system has been completely redesigned and unified. Instead of managing 5 different authentication methods with conflicting tokens and duplicate endpoints, you now have **one clean, standards-compliant OAuth2/JWT system**.

### Before → After

| Aspect | Before | After |
|--------|--------|-------|
| **Token Types** | DRF (non-expiring) + JWT | JWT only (expiring in 1 hour) |
| **Login Methods** | 5 different endpoints | 1 unified `/accounts/login/` |
| **Discovery** | 2 OIDC endpoints | 1 at `/.well-known/openid-configuration/` |
| **Maintenance** | Complex, overlapping | Simple, single standard |
| **Security** | Non-expiring tokens ❌ | Automatic expiry ✅ |

---

## 🚀 Quick Start (10 Minutes)

### Step 1: Create Test User
```bash
python manage.py shell
>>> from django.contrib.auth.models import User
>>> User.objects.create_user('testuser', 'test@example.com', 'TestPassword123!')
>>> exit()
```

### Step 2: Create OAuth2 App
Visit: http://localhost:8000/admin/oauth2_provider/application/add/
- **Name**: `Postman Test`
- **Client ID**: `postman-client`
- **Grant Type**: `Resource owner password-based`
- **Redirect URI**: `http://localhost:8888/callback`

### Step 3: Get Token (via Postman or curl)

**Postman:**
```
POST http://localhost:8000/o/token/

Body (form-data):
  grant_type: password
  username: testuser
  password: TestPassword123!
  client_id: postman-client
```

**curl:**
```bash
curl -X POST http://localhost:8000/o/token/ \
  -d "grant_type=password&username=testuser&password=TestPassword123!&client_id=postman-client"
```

### Step 4: Use Token in API Calls
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8000/api/users/profile/
```

✅ **Done!** You're now using the unified OAuth2 system.

---

## 📚 Documentation

### For Different Needs:

| Document | Best For | Read Time |
|----------|----------|-----------|
| **[POSTMAN_COMPLETE_GUIDE.md](POSTMAN_COMPLETE_GUIDE.md)** | Testing in Postman | 10 min |
| **[UNIFIED_OAUTH2_SYSTEM.md](UNIFIED_OAUTH2_SYSTEM.md)** | Complete reference | 15 min |
| **[IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md)** | What changed & why | 10 min |

### Specific Tasks:

- **I want to test the API** → Read [POSTMAN_COMPLETE_GUIDE.md](POSTMAN_COMPLETE_GUIDE.md)
- **I need to understand the flows** → Read [UNIFIED_OAUTH2_SYSTEM.md](UNIFIED_OAUTH2_SYSTEM.md#authentication-flows)
- **I'm migrating old code** → Read [IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md#migration-from-old-system)
- **I need to troubleshoot** → Read [UNIFIED_OAUTH2_SYSTEM.md](UNIFIED_OAUTH2_SYSTEM.md#troubleshooting)

---

## 🔧 System Architecture

```
┌─────────────────────────────────────────────────────┐
│                   User/Client                       │
└──────────┬──────────────────────────────┬───────────┘
           │                              │
        Browser                      API Client
        (Web)                         (Postman)
           │                              │
           └──────────────┬───────────────┘
                          │
                    ┌─────▼──────┐
                    │/accounts/  │
                    │login/      │ ◄─ Unified Entry Point
                    └─────┬──────┘
                          │
           ┌──────────────┼──────────────┐
           │              │              │
           ▼              ▼              ▼
      Org Form      Social Auth    OAuth2 Code
     (username/    (Google/FB)     (PKCE)
      password)           │              │
           │              │              │
           └──────────────┼──────────────┘
                          │
                   ┌──────▼────────┐
                   │ /o/token/     │ ◄─ Token Endpoint
                   │ (JWT + Refresh)
                   └──────┬────────┘
                          │
                    ┌─────▼──────┐
                    │JWT Token   │ ◄─ Valid for all APIs
                    │(3600 sec)  │
                    └─────┬──────┘
                          │
           ┌──────────────┼──────────────┐
           │              │              │
           ▼              ▼              ▼
         /api/        /api/oidc/      Protected
        users/       userinfo/      Resources
      profile/                       (DRF)
```

---

## 🔐 Authentication Flows

### 1. Organization Login (Simplest - Use for Testing)
```
User enters: testuser / TestPassword123!
    ↓
Django User validation
    ↓
Token generated via OAuth2
    ↓
JWT returned with 3600s expiry
```

**Endpoint**: `POST /o/token/` with `grant_type=password`

### 2. OAuth2 Authorization Code (For Web Apps)
```
User clicks "Login with Our App"
    ↓
Redirected to /o/authorize/ with PKCE challenge
    ↓
User logs in at /accounts/login/
    ↓
Authorization code returned
    ↓
Backend exchanges code for token
    ↓
JWT returned with refresh token
```

**Endpoint**: `GET /o/authorize/` then `POST /o/token/` with `grant_type=authorization_code`

### 3. Social Provider (Google/Facebook/etc)
```
User clicks "Sign in with Google"
    ↓
Redirected to Google login
    ↓
User authenticates with Google
    ↓
Redirected back with user profile
    ↓
Local user created/updated
    ↓
JWT returned with refresh token
```

**Endpoint**: `GET /social/login/google-oauth2/` (and other providers)

### 4. Token Refresh (Keep Using Without Re-login)
```
Access token expires after 3600 seconds
    ↓
Client uses refresh token to get new access token
    ↓
New JWT returned
    ↓
Refresh token rotates (new one issued)
```

**Endpoint**: `POST /o/token/` with `grant_type=refresh_token`

---

## 📋 Unified Endpoints

### Authentication Endpoints

| Method | Endpoint | Purpose | Auth Required |
|--------|----------|---------|---|
| GET | `/accounts/login/` | Show login form with social buttons | No |
| POST | `/accounts/login/` | Submit org credentials | No |
| GET | `/o/authorize/` | OAuth2 authorization | No |
| POST | `/o/token/` | Get/refresh token | No |
| GET | `/social/login/<provider>/` | Social login | No |

### OIDC/Discovery Endpoints

| Method | Endpoint | Purpose | Auth Required |
|--------|----------|---------|---|
| GET | `/.well-known/openid-configuration/` | OIDC discovery | No |
| GET | `/api/oidc/jwks/` | JWT signing keys | No |
| GET | `/api/oidc/userinfo/` | Get user info | **Bearer Token** |

### API Endpoints (Protected - Require Token)

| Method | Endpoint | Purpose | Auth Required |
|--------|----------|---------|---|
| GET | `/api/users/profile/` | Current user's profile | **Bearer Token** |
| GET | `/api/users/` | List all users (admin only) | **Bearer Token** |

---

## 🧪 Testing

### Test in Browser
1. **Login at**: http://localhost:8000/accounts/login/
2. **Enter**: testuser / TestPassword123!
3. **See**: Organization login form with social buttons

### Test in Postman
1. **Import**: `HCS_SSO_OAuth2_Postman_Collection.json`
2. **Get Token**: Use "Get Token with Username/Password" request
3. **Use Token**: Replace `YOUR_ACCESS_TOKEN` in API requests
4. **See**: User profile returned as JSON

### Test with curl
```bash
# Get token
TOKEN=$(curl -s -X POST http://localhost:8000/o/token/ \
  -d "grant_type=password&username=testuser&password=TestPassword123!&client_id=postman-client" \
  | jq -r '.access_token')

# Use token
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/users/profile/ | jq
```

### Run Diagnostic
```bash
python manage.py shell < diagnostic.py
```

This checks all configurations and reports any issues.

---

## 📦 Files Changed

### Modified Files

| File | Changes |
|------|---------|
| [apps/users/views.py](apps/users/views.py) | Removed CustomAuthToken class |
| [apps/users/urls.py](apps/users/urls.py) | Removed `/api/users/login/` endpoint |
| [apps/oidc/urls.py](apps/oidc/urls.py) | Removed duplicate well-known endpoint |
| [templates/registration/login.html](templates/registration/login.html) | Added social provider buttons |
| [sso/settings.py](sso/settings.py) | Unified auth settings, changed LOGIN_URL |
| [sso/urls.py](sso/urls.py) | Removed choice page, added redirect |

### New Files Created

| File | Purpose |
|------|---------|
| [HCS_SSO_OAuth2_Postman_Collection.json](HCS_SSO_OAuth2_Postman_Collection.json) | Postman import file with all flows |
| [UNIFIED_OAUTH2_SYSTEM.md](UNIFIED_OAUTH2_SYSTEM.md) | Complete reference documentation |
| [POSTMAN_COMPLETE_GUIDE.md](POSTMAN_COMPLETE_GUIDE.md) | Step-by-step testing guide |
| [IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md) | What changed and why |
| [diagnostic.py](diagnostic.py) | System health check script |

---

## 🔒 Security Features

### ✅ Token Security
- **Type**: JWT with RSA-2048 signature (industry standard)
- **Expiry**: 3600 seconds automatic expiration
- **Refresh**: Automatic refresh token rotation
- **Storage**: Encrypted in database
- **Signature**: Verified against JWKS endpoint

### ✅ Request Security
- **PKCE**: Required for all public clients (mobile, SPAs)
- **CSRF**: Django middleware protection on all forms
- **State**: OAuth2 CSRF protection parameter
- **HTTPS**: Enforced in production settings

### ✅ Scope Control
- OpenID Connect compliance
- Profile scope for user data
- Email scope for contact info
- Custom scopes for fine-grained permissions

### ✅ Removed Insecure Methods
- ❌ DRF Token authentication (non-expiring)
- ❌ Plain text passwords in responses
- ❌ Custom token formats

---

## 🚨 Breaking Changes

### Old Code Won't Work

**DRF Token Auth (REMOVED)**:
```python
# ❌ This no longer works:
curl -H "Authorization: Token abc123xyz" http://localhost:8000/api/users/
```

**Update to OAuth2**:
```python
# ✅ Use this instead:
curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9..." http://localhost:8000/api/users/
```

### Old Endpoint (REMOVED)

**`/api/users/login/` endpoint deleted**:
```python
# ❌ This no longer exists:
curl -X POST http://localhost:8000/api/users/login/ \
  -d '{"username": "test", "password": "pass"}'
```

**Use `/o/token/` instead**:
```python
# ✅ Use this endpoint:
curl -X POST http://localhost:8000/o/token/ \
  -d "grant_type=password&username=test&password=pass&client_id=your_app"
```

### Response Format Changed

**Old DRF Token Response**:
```json
{"token": "abc123xyz"}
```

**New OAuth2 Response**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "xyz789abc...",
  "id_token": "eyJhbGciOiJSUzI1NiJ9..."
}
```

---

## 🛠️ Common Tasks

### Add New User
```bash
python manage.py shell
>>> from django.contrib.auth.models import User
>>> User.objects.create_user('newuser', 'new@example.com', 'SecurePassword123!')
```

### Create OAuth2 App Programmatically
```bash
python manage.py shell
>>> from oauth2_provider.models import Application
>>> from django.contrib.auth.models import User
>>> user = User.objects.first()
>>> app = Application.objects.create(
...   name='My App',
...   client_id='my-app-client',
...   user=user,
...   client_type='public',
...   authorization_grant_type='password',
...   redirect_uris='https://myapp.example.com/callback'
... )
```

### Check Registered Apps
```bash
python manage.py shell
>>> from oauth2_provider.models import Application
>>> for app in Application.objects.all():
...   print(f"{app.name}: {app.client_id}")
```

### Reset Database (⚠️ Deletes All Data)
```bash
rm db.sqlite3
python manage.py migrate
python manage.py createsuperuser
```

---

## 📞 Troubleshooting

### "Invalid Client ID"
✅ Solution:
1. Visit `/admin/oauth2_provider/application/`
2. Verify app exists
3. Copy exact client ID
4. Use in request

### "Invalid Redirect URI"
✅ Solution:
1. Check registered redirect URIs in app
2. Match exactly (case-sensitive, protocol+port)
3. For testing: register `http://localhost:8888/callback`

### "Access Token Expired"
✅ Solution:
```bash
# Get new token with refresh token
curl -X POST http://localhost:8000/o/token/ \
  -d "grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN&client_id=postman-client"
```

### "PKCE Required"
✅ Solution (for authorization code flow):
1. Generate random string 43-128 chars (code_verifier)
2. SHA256 hash it (code_challenge)
3. Base64url encode it
4. Add to `/o/authorize/` request

See [POSTMAN_COMPLETE_GUIDE.md](POSTMAN_COMPLETE_GUIDE.md#authorization-code-flow-for-web-apps) for example.

### Social Login Not Working
✅ Solution:
1. Go to `/admin/socialaccount/socialapp/`
2. Verify provider app credentials added
3. Check provider name matches (`google-oauth2`, `facebook`, etc)
4. Test at `/social/login/PROVIDER/`

---

## 📊 Comparison: Old vs New

### Token System

| Feature | Old (DRF Token) | New (OAuth2 JWT) |
|---------|---|---|
| **Format** | `Token abc123xyz` | `Bearer eyJhbGc...` |
| **Expiry** | Never (lifetime) ❌ | 3600 seconds ✅ |
| **Refresh** | Manual re-auth | Automatic ✅ |
| **Signature** | None | RSA-2048 ✅ |
| **Standard** | DRF custom | OAuth2/OIDC ✅ |
| **Verification** | Database lookup | Cryptographic ✅ |

### Login Methods

| Flow | Old System | New System |
|------|---|---|
| **Organization** | `/accounts/login/` | `/accounts/login/` (same) |
| **OAuth2 Auth Code** | `/o/authorize/` + `/o/token/` | `/o/authorize/` + `/o/token/` (same) |
| **Password Grant** | `/api/users/login/` | `/o/token/` |
| **Social** | `/social/login/` | `/social/login/` (same) |
| **Choice Page** | `/login/` | Removed ✅ |

---

## ✨ Next Steps (Optional Enhancements)

After verifying the unified system works:

1. **Email Verification** - Require email confirmation for new users
2. **Multi-Factor Authentication** - Add 2FA for security
3. **Rate Limiting** - Limit login attempts to prevent brute force
4. **Audit Logging** - Log all authentication events
5. **Session Management** - View and revoke active sessions
6. **Password Policy** - Enforce strong passwords
7. **Account Lockout** - Lock after failed attempts
8. **Consent Screen** - Show scope approval before 1st use

---

## 📖 Additional Resources

### Official Documentation
- [OAuth2 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519)

### Libraries Used
- [django-oauth-toolkit](https://django-oauth-toolkit.readthedocs.io/) - OAuth2 provider
- [django-social-auth](https://python-social-auth.readthedocs.io/) - Social authentication
- [djangorestframework](https://www.django-rest-framework.org/) - REST API

### Tools
- [jwt.io](https://jwt.io/) - Decode/verify JWT tokens
- [Postman](https://www.postman.com/) - API testing

---

## 🎉 Summary

Your authentication system is now:

✅ **Unified** - Single OAuth2/JWT standard  
✅ **Secure** - Expiring tokens, RSA signatures  
✅ **Standard** - OIDC compliant, widely supported  
✅ **Simple** - Easy to understand and maintain  
✅ **Flexible** - Supports all auth flows  

**Start testing now:**
```bash
python manage.py runserver
```

Then visit:
- **Web**: http://localhost:8000/accounts/login/
- **API**: Import `HCS_SSO_OAuth2_Postman_Collection.json` in Postman
- **Health**: Run `python manage.py shell < diagnostic.py`

---

**Version**: 1.0 - Unified OAuth2/JWT System  
**Status**: ✅ Production Ready  
**Last Updated**: 2024

