# Authentication Flow Audit & Duplicacy Review

**Date**: 11 February 2026  
**Project**: HCS SSO with OAuth2/OIDC  
**Status**: ⚠️ ISSUES FOUND - See recommendations below

---

## Executive Summary

The authentication system has **multiple overlapping authentication methods** with some **duplicacy and architectural conflicts**. This creates confusion in the flow and potential security/routing issues.

### Key Issues Found:
1. ✗ **Duplicate Login Endpoints** - Three different login paths
2. ✗ **Conflicting Redirect Behavior** - Multiple systems trying to manage redirects
3. ✗ **Two Token Authentication Systems** - REST Token + OAuth2
4. ✗ **OIDC Configuration Duplication** - Wells-known endpoint defined in two places
5. ✗ **Social Auth Namespace Conflicts** - django-social-auth + custom social views
6. ⚠️ **Unclear Flow for Postman/API Clients** - Missing guidance on which method to use

---

## 1. AUTHENTICATION METHODS ANALYSIS

### Current Authentication Pathways:

```
┌─────────────────────────────────────────────────────────┐
│         AUTHENTICATION METHODS (TOO MANY!)              │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. ORGANIZATION LOGIN (HTML Form)                      │
│     └─ /accounts/login/ (OrganizationLoginView)        │
│        └─ Uses Django session + AuthenticationForm      │
│           └─ Returns HTML redirect                      │
│                                                         │
│  2. TOKEN-BASED LOGIN (REST API)                        │
│     └─ /api/users/login/ (CustomAuthToken)             │
│        └─ Username/password → Returns JSON token       │
│           └─ Uses DRF Token Authentication             │
│                                                         │
│  3. OAUTH2 AUTHORIZATION (Delegated)                    │
│     └─ /o/authorize/ (django-oauth-toolkit)            │
│        └─ Redirects to LOGIN_URL (/login/)             │
│           └─ Can use either org or social              │
│                                                         │
│  4. SOCIAL PROVIDER AUTH (External)                     │
│     └─ /social/login/<provider>/                        │
│     └─ /api/social/login/<provider>/                    │
│        └─ Two different endpoints for same thing        │
│           └─ Returns session OR token                   │
│                                                         │
│  5. USER REGISTRATION (Create Account)                  │
│     └─ /api/users/register/ (UserRegistrationView)     │
│        └─ Creates user + returns token                 │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Problem**: A Postman client doesn't know which flow to use!

---

## 2. DUPLICACY & CONFLICTS

### 2.1 Duplicate Login Endpoints

| Endpoint | Method | Type | Returns | Auth Backend |
|----------|--------|------|---------|--------------|
| `/accounts/login/` | POST | HTML Form | Session/Redirect | ModelBackend |
| `/api/users/login/` | POST | REST API | Token (JSON) | ModelBackend |
| `/o/authorize/` | GET | OAuth2 | Session/Redirect | OAuth2Provider |
| Social endpoints (2 versions) | POST | REST + django-social-auth | Session/Token | Mixed |

**Impact**: 
- Confusing for API clients
- Multiple ways to authenticate
- Different return types
- Inconsistent behavior

### 2.2 OIDC Well-Known Endpoint Defined Twice

**Location 1**: `sso/urls.py` line 44
```python
path('.well-known/openid-configuration/', WellKnownConfigurationView.as_view(), name='oidc-well-known'),
```

**Location 2**: `apps/oidc/urls.py` (included under `/api/oidc/`)
```python
path('.well-known/openid-configuration/', WellKnownConfigurationView.as_view(), name='oidc-well-known'),
```

**Result**:
- ✓ `/.well-known/openid-configuration/` works (main project URL)
- ✓ `/api/oidc/.well-known/openid-configuration/` also works (redundant)
- **Issue**: Clients might hit the wrong one

### 2.3 Social Authentication - Two Parallel Systems

**System A: django-social-auth** (Project-level)
```
/social/login/<provider>/        → Provider redirect
/social/complete/<provider>/     → Provider callback (auto-handled)
Uses: AUTHENTICATION_BACKENDS with social_core backends
```

**System B: Custom API Endpoints** (Under `/api/social/`)
```
/api/social/login/<provider>/    → Custom view
/api/social/callback/<provider>/ → Custom callback
Uses: Custom views in apps/social/views.py
```

**Issue**: Two ways to do social auth!
- Django project includes both systems
- SOCIAL_AUTH_LOGIN_URL points to /login/ (django-social-auth)
- But custom views are also available
- User/developer confusion

### 2.4 Token Authentication Systems (Two!)

**System A: DRF Token Authentication**
```
Token endpoint: /api/users/login/
Returns: {"token": "abc123xyz...", "user": {...}}
Used by: REST Framework views with TokenAuthentication
Storage: rest_framework.authtoken.models.Token
Expiry: None (tokens don't expire)
```

**System B: OAuth2/JWT Tokens**
```
Token endpoint: /o/token/
Returns: {"access_token": "eyJ...", "id_token": "...", "refresh_token": "..."}
Used by: OAuth2-protected views
Storage: oauth2_provider models
Expiry: 3600 seconds (configurable)
```

**Issue**: 
- Different token formats
- Different expiry policies
- Different authentication methods
- Which should Postman use?

---

## 3. AUTHENTICATION FLOW CHART (Current Mess)

```
External Client Request
        │
        ├─────────────────┬────────────────┬──────────────┐
        ▼                 ▼                ▼              ▼
   Browser Form    REST API Client   OAuth2 Client  Social Auth
        │                │                │              │
        │                │                │              │
        ├──────────┬──────┘                │              │
        ▼          ▼                       ▼              ▼
   /accounts/  /api/users/          /o/authorize/  /social/login/
    login/      login/                              /api/social/login/
        │         │                        │              │
        ├─ POST ──┤                        ├──────────────┤
        │         │                        │              │
        ▼         ▼                        ▼              ▼
    Validate  CustomAuthToken        OAuth2Provider    Social Backend
    Creds     (REST Token)           (Checks auth)     (External)
        │         │                        │              │
        ▼         ▼                        ▼              ▼
   Session    Token                  Not authed?     Provider Auth
   Created    Returned                Redirect to /login/
        │         │                        │              │
        ▼         ▼                        ▼              ▼
   Redirect   Return JSON          Scope Consent   User Created
   to home    (200 OK)             Screen          Session Created
        │         │                        │              │
        │         │                        ▼              │
        │         │                    Auth Code       Redirect
        │         │                    Generated       to /profile/
        │         │                        │              │
        └─────────┴────────────────────────┴──────────────┘
                          │
                    User is Authenticated
                          │
                    Use different tokens!
```

---

## 4. SETTINGS CONFIGURATION ISSUES

### 4.1 Multiple Login URL Configurations

```python
# settings.py

# 1. Django's built-in (line 136-138)
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'

# 2. Social Auth's (line 153-158)
SOCIAL_AUTH_URL_NAMESPACE = 'social'
SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/'
SOCIAL_AUTH_LOGIN_ERROR_URL = '/login-error/'
SOCIAL_AUTH_LOGOUT_REDIRECT_URL = '/'
SOCIAL_AUTH_NEW_USER_REDIRECT_URL = '/profile/'
SOCIAL_AUTH_LOGIN_URL = '/login/'

# 3. OAuth2 Provider (line 224-260)
OAUTH2_PROVIDER = {
    'PKCE_REQUIRED': True,
    'SCOPES': {...},
    ...
}
```

**Issue**: 
- Django LOGIN_URL and SOCIAL_AUTH_LOGIN_URL both point to `/login/`
- But `/login/` only shows choice page, not actual login form
- Actual org form is at `/accounts/login/`
- This works by accident because user clicks "HCS Account" button
- But if OAuth2 redirects directly, might skip the choice page

---

## 5. URL ROUTING COMPLEXITY

### Main Project URLs (sso/urls.py)
```
✓ /                              → index.html
✓ /login/                        → login.html (choice page)
✓ /accounts/login/               → OrganizationLoginView (form)
✓ /accounts/profile/             → profile.html
✓ /admin/                        → Django admin
✓ /accounts/                     → Django auth URLs (password reset, etc)
✓ /o/                            → OAuth2Provider URLs
✓ /social/                       → django-social-auth URLs
✓ /api/users/                    → User management APIs
✓ /api/oidc/                     → OIDC endpoints
✓ /api/social/                   → Custom social endpoints
✓ /.well-known/openid-configuration/  → OIDC discovery
✓ /__debug__/                    → Debug toolbar (dev only)
```

### Conflicts/Duplicacy:
1. `/social/` (django-social-auth) + `/api/social/` (custom) = Two social systems
2. `/.well-known/` + `/api/oidc/.well-known/` = OIDC endpoint defined twice
3. `/api/users/login/` + `/accounts/login/` = Two login endpoints

---

## 6. AUTHENTICATION BACKENDS (settings.py line 141-149)

```python
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',           # Org creds
    'social_core.backends.google.GoogleOAuth2',            # Google
    'social_core.backends.facebook.FacebookOAuth2',        # Facebook
    'social_core.backends.microsoft.MicrosoftOAuth2',      # Microsoft
    'social_core.backends.github.GithubOAuth2',            # GitHub
    'social_core.backends.linkedin.LinkedinOAuth2',        # LinkedIn
    'social_core.backends.open_id_connect.OpenIdConnectAuth',  # Generic OIDC
]
```

**Problem**: 
- All backends are tried in order
- If user provides email for org login, it might match social backend first
- No clear routing between backends
- OAuth2 provider uses its own authentication (separate from these backends)

---

## 7. SESSION VS TOKEN INCONSISTENCY

| Aspect | Organization Form | REST Token | OAuth2 |
|--------|-------------------|-----------|--------|
| Endpoint | `/accounts/login/` | `/api/users/login/` | `/o/authorize/` |
| Auth Method | HTML Form | JSON | OAuth2 Flow |
| Storage | Session Cookie | Token DB | Access Token |
| Expiry | Browser Close | None | 3600 sec |
| Format | Django Session | DRF Token | JWT |
| Used By | Browser Clients | REST Clients | 3rd Party Apps |
| Return Type | Redirect | JSON | Redirect Code |

**Problem**: 
- No unified authentication model
- Different tokens mean API calls need different auth methods
- Postman users don't know which to use

---

## 8. CRITICAL ISSUE: POSTMAN FLOW

**Why Postman isn't working properly:**

When using Postman with OAuth2 flow:
1. Postman sends: `GET /o/authorize/?client_id=...`
2. Server checks: Is user authenticated?
3. If NO: Redirects to `LOGIN_URL (/login/)`
4. Postman receives redirect response
5. **Postman doesn't follow HTML redirects automatically** in OAuth2 handler
6. Shows error: "Not redirecting"

**Root Cause**: 
- Postman expects OAuth2 to show a login form
- But instead, it redirects to a choice page
- Postman doesn't know how to handle the redirect
- The configuration assumes a browser client

---

## 9. SECURITY CONCERNS

1. **Token Reuse**: DRF tokens don't expire (security issue)
2. **Mixed Auth Methods**: Hard to audit which method users are using
3. **Unclear Scope Consent**: OAuth2 shows consent, but session-based doesn't
4. **Social Backend Order**: First matching backend wins (could be wrong one)
5. **Duplicate OIDC Endpoints**: Clients might hit different endpoints unexpectedly

---

## 10. RECOMMENDATIONS

### Priority 1: Fix Postman/API Flow ⚠️ URGENT

**Solution**: Create a unified API authentication endpoint

```python
# NEW: apps/core/views.py
class UnifiedAuthenticationView(APIView):
    """
    Unified authentication endpoint for API clients (REST & OAuth2)
    
    Handles both:
    1. Direct token requests (for REST clients)
    2. OAuth2 authorization (for delegated access)
    
    Returns consistent JWT tokens (not mixed DRF tokens)
    """
    
    def post(self, request):
        grant_type = request.data.get('grant_type')
        
        if grant_type == 'password':
            # Username/password login
            return self.handle_password_grant(request)
        elif grant_type == 'authorization_code':
            # OAuth2 code exchange
            return self.handle_auth_code_grant(request)
        # ... etc
```

### Priority 2: Remove Duplicacy

**A. Remove DRF Token Authentication**
- DELETE: `CustomAuthToken` view from `/api/users/login/`
- REPLACE: Use OAuth2/JWT tokens exclusively
- REASON: Two token systems are confusing

**B. Consolidate Social Auth**
- REMOVE: Custom `/api/social/` endpoints
- KEEP: django-social-auth at `/social/`
- REASON: Single source of truth

**C. Remove Duplicate OIDC Endpoint**
- KEEP: `/.well-known/openid-configuration/` (main project URL)
- REMOVE: Duplicate from `/api/oidc/.well-known/`
- REASON: Standard location for OIDC discovery

### Priority 3: Fix Authentication Flow

**Current (Broken)**:
```
OAuth2 Request → /o/authorize/ → Not authed? → /login/ (choice)
                                 → Click "HCS" → /accounts/login/ (form)
                                 → Post form → Redirect back to OAuth2
```

**Fixed**:
```
OAuth2 Request → /o/authorize/ → Not authed? → /accounts/login/ (direct to form)
                                 → Post form → Redirect back to OAuth2

OR (for API)

API Request → /api/auth/token/ → {grant_type, username, password} → JWT Token
```

**Implementation**:
```python
# sso/urls.py - CHANGE
# OLD:
path('login/', TemplateView.as_view(template_name='login.html'), name='login'),
path('accounts/login/', OrganizationLoginView.as_view(), name='organization_login'),

# NEW:
# Make /accounts/login/ handle BOTH form submission AND choice page
# OR: Make OAuth2 skip /login/ choice and go directly to org login
```

### Priority 4: Standardize Settings

```python
# sso/settings.py - CONSOLIDATE AUTH SETTINGS

# REMOVE separate social auth settings
# MOVE: Everything under single AUTH configuration

AUTH_SETTINGS = {
    # Organization
    'organization_login_url': '/accounts/login/',
    'organization_backend': 'django.contrib.auth.backends.ModelBackend',
    
    # OAuth2
    'oauth2_authorization_url': '/o/authorize/',
    'oauth2_token_url': '/o/token/',
    'oauth2_required_scopes': ['openid', 'profile', 'email'],
    
    # Social
    'social_login_url': '/social/login/',
    'social_backends': ['google', 'facebook', 'microsoft', 'github', 'linkedin'],
    
    # Redirect behavior
    'login_url': '/accounts/login/',  # Where to send unauthenticated users
    'login_redirect_url': '/',         # After successful login
    'logout_redirect_url': '/',        # After logout
}
```

### Priority 5: Clear Documentation for Postman

Create Postman collection with:
1. **OAuth2 Flow** - For 3rd party apps
2. **Token Flow** - For API clients (using username/password)
3. **Social Flow** - For testing social login
4. **Examples** - with real requests

---

## 11. IMPLEMENTATION ROADMAP

### Phase 1: Document Current State ✓ (Done)
- This audit document

### Phase 2: Consolidate Authentication (1-2 hours)
- [ ] Keep only OAuth2/JWT tokens (remove DRF tokens)
- [ ] Remove duplicate OIDC endpoint
- [ ] Consolidate social auth (remove `/api/social/`)

### Phase 3: Fix Postman Flow (2-3 hours)
- [ ] Make OAuth2 redirect directly to form (not choice page)
- [ ] OR: Create unified API auth endpoint
- [ ] Test with Postman

### Phase 4: Update Documentation (1 hour)
- [ ] Update guides with single auth method recommendation
- [ ] Create Postman collection
- [ ] Add flow diagrams

### Phase 5: Refactor URLs (1-2 hours)
- [ ] Simplify routing
- [ ] Remove redundant endpoints
- [ ] Add 301 redirects for deprecated URLs

---

## 12. SUMMARY TABLE

| Issue | Severity | Fix Effort | Impact |
|-------|----------|-----------|--------|
| Duplicate login endpoints | HIGH | 2-3h | Postman fails |
| Two token systems | HIGH | 3-4h | Security + Confusion |
| Duplicate OIDC endpoints | MEDIUM | 1h | Minor confusion |
| Two social auth systems | MEDIUM | 2-3h | Maintenance burden |
| Unclear settings | MEDIUM | 1-2h | Documentation issue |
| TOTAL | - | 9-13h | Fix recommended |

---

## 13. FINAL RECOMMENDATION

**Immediate Action**: 
Focus on **Priority 1 & 2** to fix Postman flow and remove duplicacy. This will:
- ✓ Make Postman work
- ✓ Simplify codebase
- ✓ Improve security
- ✓ Reduce maintenance

**Estimated Timeline**: 
- **Quick Fix (3-4 hours)**: Get Postman working
- **Proper Fix (9-13 hours)**: Full refactor as recommended
- **Documentation (1-2 hours)**: Update guides

Would you like me to implement these changes?

