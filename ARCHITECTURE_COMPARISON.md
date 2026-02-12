# Current vs Recommended Architecture

## Current Architecture (Complex - 5 Auth Methods)

```
┌─────────────────────────────────────────────────────────────────┐
│                    CURRENT SSO SYSTEM                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  BROWSER CLIENT                                                 │
│  │                                                              │
│  ├─ Visit /o/authorize/                                        │
│  │  ├─ Not authenticated                                       │
│  │  └─ Redirect to /login/ (CHOICE PAGE)                       │
│  │     ├─ Click "HCS Account"                                  │
│  │     └─ Redirect to /accounts/login/                         │
│  │        ├─ POST username/password                            │
│  │        └─ Create Django session                             │
│  │           └─ Redirect back to /o/authorize/                 │
│  │              ├─ Now authenticated                           │
│  │              └─ Show scope consent                          │
│  │                 ├─ Click Authorize                          │
│  │                 └─ Get OAuth2 token                         │
│  │                    └─ Return to app with code               │
│  │                       └─ Exchange code for JWT              │
│  │                                                              │
│  └─ Alternative: Click social provider                         │
│     ├─ Redirect to provider                                    │
│     ├─ Provider authenticates                                  │
│     └─ Back to /social/complete/ → Create session             │
│        └─ Back to /o/authorize/                                │
│           └─ Same as above                                     │
│                                                                 │
│  ────────────────────────────────────────────────────────────  │
│                                                                 │
│  REST API CLIENT (Postman)                                     │
│  │                                                              │
│  ├─ Option A: POST to /api/users/login/                        │
│  │  ├─ Username/password                                       │
│  │  └─ Get DRF Token (never expires)                           │
│  │     └─ Different from OAuth2 token! ⚠️                      │
│  │                                                              │
│  └─ Option B: OAuth2 flow (problematic)                        │
│     ├─ Try /o/authorize/                                       │
│     ├─ Get redirected to /login/                               │
│     ├─ Postman can't handle HTML redirect ❌                   │
│     └─ Fails                                                   │
│                                                                 │
│  ────────────────────────────────────────────────────────────  │
│                                                                 │
│  SOCIAL AUTH CLIENT                                            │
│  │                                                              │
│  └─ POST to /api/social/login/<provider>/ (custom)             │
│     └─ OR /social/login/<provider>/ (django-social-auth)       │
│        └─ Two systems doing same thing! ⚠️                     │
│                                                                 │
│  ────────────────────────────────────────────────────────────  │
│                                                                 │
│  Token Returns:                                                │
│  │                                                              │
│  ├─ /api/users/login/ → DRF Token (string)                     │
│  │  └─ Format: "abc123xyz"                                     │
│  │  └─ No expiry                                               │
│  │  └─ Stored in DB: rest_framework.authtoken.Token            │
│  │                                                              │
│  ├─ /o/token/ → JWT (JSON)                                     │
│  │  └─ Format: {"access_token": "eyJ...", "expires_in": 3600}  │
│  │  └─ Expires in 1 hour                                       │
│  │  └─ Stored in DB: oauth2_provider.AccessToken               │
│  │                                                              │
│  └─ /api/social/ → Varies (session or token)                   │
│     └─ Inconsistent ⚠️                                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

PROBLEMS:
❌ 5 different authentication methods
❌ 2 different token systems (DRF + JWT)
❌ Postman can't use OAuth2 flow
❌ Social auth duplicated (2 systems)
❌ Confusing for developers
❌ Hard to maintain
❌ Security issues (non-expiring tokens)
```

---

## Recommended Architecture (Simple - 1 Auth Method)

```
┌─────────────────────────────────────────────────────────────────┐
│                 RECOMMENDED SSO SYSTEM                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │      UNIFIED OAUTH2/JWT AUTHENTICATION SYSTEM           │  │
│  │      (Single source of truth)                           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ALL flows use: /o/ (OAuth2 provider)                          │
│  ALL tokens are: JWT format                                    │
│  ALL tokens expire: 3600 seconds (configurable)                │
│                                                                 │
│  ────────────────────────────────────────────────────────────  │
│                                                                 │
│  BROWSER CLIENT (HTML Forms)                                   │
│  │                                                              │
│  ├─ Visit /o/authorize/                                        │
│  │  ├─ Not authenticated                                       │
│  │  └─ Redirect to /accounts/login/                            │
│  │     ├─ (NO choice page - direct to form)                    │
│  │     ├─ Can add form to show alternatives:                   │
│  │     │  - Username/password form                             │
│  │     │  - Google button                                      │
│  │     │  - Facebook button                                    │
│  │     │  - etc.                                               │
│  │     └─ User chooses method and authenticates                │
│  │        └─ Redirect back to /o/authorize/                    │
│  │           ├─ Now authenticated                              │
│  │           └─ Show scope consent                             │
│  │              ├─ Click Authorize                             │
│  │              └─ Return authorization code                   │
│  │                                                              │
│  ├─ Organization Password:                                     │
│  │  ├─ POST username + password to /accounts/login/            │
│  │  └─ Django session created                                  │
│  │                                                              │
│  └─ Social Provider:                                           │
│     ├─ Click provider button at /accounts/login/               │
│     ├─ Redirect to /social/login/<provider>/                   │
│     └─ Provider authenticates                                  │
│        └─ Back to /accounts/login/ → session created           │
│                                                                 │
│  ────────────────────────────────────────────────────────────  │
│                                                                 │
│  REST API CLIENT (Postman & Mobile)                            │
│  │                                                              │
│  ├─ Token Request (Resource Owner Password Grant)              │
│  │  ├─ POST /o/token/                                          │
│  │  │  ├─ grant_type=password                                  │
│  │  │  ├─ username=testuser                                    │
│  │  │  ├─ password=TestPass123!                                │
│  │  │  └─ client_id=YOUR_CLIENT_ID                             │
│  │  └─ Response:                                               │
│  │     ├─ access_token: "eyJ..." (JWT)                         │
│  │     ├─ token_type: "Bearer"                                 │
│  │     ├─ expires_in: 3600                                     │
│  │     └─ refresh_token: "abc123..." (for renewal)             │
│  │        └─ Use in API calls:                                 │
│  │           Authorization: Bearer eyJ...                      │
│  │                                                              │
│  └─ OAuth2 Code Flow (3rd party apps)                          │
│     ├─ Same as browser flow                                    │
│     └─ API handles code exchange internally                    │
│        └─ Get access token + refresh token                     │
│                                                                 │
│  ────────────────────────────────────────────────────────────  │
│                                                                 │
│  SOCIAL AUTH (Google, Facebook, etc.)                          │
│  │                                                              │
│  ├─ From browser: /accounts/login/ → click Google button       │
│  │  ├─ Redirect to Google                                      │
│  │  ├─ Google authenticates                                    │
│  │  └─ Back to /social/login/google/complete/                 │
│  │     ├─ Create/update user                                   │
│  │     └─ Django session created                               │
│  │        └─ Redirect back to /o/authorize/                    │
│  │           └─ OAuth2 flow continues                          │
│  │                                                              │
│  └─ From API: POST /o/token/                                   │
│     ├─ grant_type=assertion                                    │
│     ├─ assertion=<social_token>                                │
│     └─ Get access token                                        │
│        └─ Same JWT format                                      │
│                                                                 │
│  ────────────────────────────────────────────────────────────  │
│                                                                 │
│  SINGLE TOKEN SYSTEM:                                          │
│  │                                                              │
│  └─ All tokens from /o/token/                                  │
│     ├─ Format: JWT with claims                                 │
│     │  {                                                       │
│     │    "iss": "http://localhost:8000",                       │
│     │    "sub": "user_id",                                     │
│     │    "aud": "client_id",                                   │
│     │    "exp": timestamp+3600,                                │
│     │    "iat": timestamp,                                     │
│     │    "name": "User Name",                                  │
│     │    "email": "user@hcs.gov"                               │
│     │  }                                                       │
│     │                                                          │
│     ├─ Expiry: 3600 seconds (secure)                           │
│     ├─ Refresh: Use refresh_token to get new token             │
│     └─ Verify: Using JWKS endpoint (/.well-known/jwks/)        │
│                                                                 │
│  ────────────────────────────────────────────────────────────  │
│                                                                 │
│  DELETED ENDPOINTS:                                            │
│  ├─ ❌ /api/users/login/ (replaced by /o/token/)               │
│  ├─ ❌ /login/ choice page (merged into /accounts/login/)      │
│  ├─ ❌ /api/social/login/ (use /social/login/)                 │
│  └─ ❌ /api/oidc/.well-known/ (use /.well-known/)              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

BENEFITS:
✓ Single authentication method
✓ All tokens are JWT (secure, expiring)
✓ Postman works perfectly
✓ API clients consistent with browsers
✓ Social auth single system
✓ Easier to understand and maintain
✓ Follows OAuth2 standards
✓ More secure (no non-expiring tokens)
```

---

## Side-by-Side Comparison

### Token Comparison

| Aspect | Current (DRF) | Current (OAuth2) | Recommended |
|--------|---------------|-----------------|-------------|
| Endpoint | `/api/users/login/` | `/o/token/` | `/o/token/` |
| Format | String: "abc123" | JWT | JWT |
| Expiry | None ❌ | 3600 sec ✓ | 3600 sec ✓ |
| Refresh | No ❌ | Yes ✓ | Yes ✓ |
| Revoke | No ❌ | Yes ✓ | Yes ✓ |
| Scope Support | No ❌ | Yes ✓ | Yes ✓ |
| Storage | DB token table | DB token table | DB token table |
| Security | Low ❌ | High ✓ | High ✓ |

### Endpoint Comparison

| Purpose | Current | Recommended | Status |
|---------|---------|-------------|--------|
| Org Login (Form) | `/accounts/login/` | `/accounts/login/` | Keep ✓ |
| Org Login (API) | `/api/users/login/` | `/o/token/` (password grant) | Consolidate |
| OAuth2 Auth | `/o/authorize/` | `/o/authorize/` | Keep ✓ |
| OAuth2 Token | `/o/token/` | `/o/token/` | Keep ✓ |
| Social Login | `/social/login/<p>/` + `/api/social/login/<p>/` | `/social/login/<p>/` | Consolidate |
| OIDC Discovery | `/.well-known/` + `/api/oidc/.well-known/` | `/.well-known/` | Consolidate |
| OIDC UserInfo | `/api/oidc/userinfo/` | `/api/oidc/userinfo/` | Keep ✓ |
| OIDC JWKS | `/api/oidc/jwks/` | `/api/oidc/jwks/` | Keep ✓ |

### Postman Flow Comparison

#### Current (Broken)
```
1. Postman: GET /o/authorize/?...
2. Server: Redirect to /login/ (HTML page)
3. Postman: ❌ Can't handle redirect
4. Postman: ERROR - Flow failed
```

#### Recommended (Works!)
```
1. Postman: POST /o/token/ (with credentials)
   {
     "grant_type": "password",
     "username": "testuser",
     "password": "TestPass123!",
     "client_id": "YOUR_ID"
   }

2. Server: Validate credentials
3. Server: Return JWT token
   {
     "access_token": "eyJ...",
     "expires_in": 3600
   }

4. Postman: ✓ Success!
5. Use token in API calls:
   Authorization: Bearer eyJ...
```

---

## Migration Path (How to Get There)

### Step 1: Deprecate DRF Token (Don't delete yet)
- Add deprecation warning to `/api/users/login/`
- Document migration path
- Let existing users migrate gradually

### Step 2: Update Documentation
- Show new `/o/token/` endpoint
- Provide migration guide
- Update Postman collection

### Step 3: Remove After Deprecation Period (3-6 months)
- Delete `/api/users/login/` endpoint
- Delete related code
- Update API docs

### Step 4: Consolidate Social Auth
- Remove `/api/social/` endpoints
- Redirect old URLs to `/social/`
- Document the change

### Step 5: Merge Login Pages
- Remove `/login/` choice page
- Add choice form to `/accounts/login/`
- OR: Keep choice page but link directly to form

---

## Code Changes Required

### 1. Delete These Files/Code
```
- CustomAuthToken view (apps/users/views.py)
- /api/users/login/ endpoint (apps/users/urls.py)
- /api/social/ endpoints (apps/social/)
- Duplicate OIDC endpoint (apps/oidc/urls.py)
```

### 2. Modify These Views
```
- OrganizationLoginView
  ├─ Add alternative login methods
  ├─ Add Google button
  ├─ Add Facebook button
  └─ Keep form submission
  
- OAuth2 Provider config
  ├─ Ensure password grant enabled
  ├─ Ensure proper scopes
  └─ Ensure proper token expiry
```

### 3. Update These Settings
```
- Remove DRF token configuration
- Consolidate auth settings
- Remove duplicate redirects
- Add password grant config to OAuth2
```

### 4. Update Documentation
```
- Postman collection
- Flow diagrams
- Setup guides
- API documentation
```

---

## Timeline & Effort

```
Phase 1: Deprecation & Migration (Week 1)
├─ Add deprecation warnings
├─ Document migration path
├─ Update all documentation
└─ Time: 2-3 hours

Phase 2: Update Endpoints (Week 2)
├─ Delete DRF token code
├─ Consolidate social auth
├─ Merge login pages
└─ Time: 3-4 hours

Phase 3: Testing (Week 2-3)
├─ Test all flows
├─ Test Postman OAuth2
├─ Test API clients
└─ Time: 2-3 hours

Phase 4: Deployment (Week 3)
├─ Deploy to staging
├─ Final testing
├─ Deploy to production
└─ Time: 1 hour

Total: ~9-11 hours over 3 weeks
```

---

## Conclusion

| Aspect | Current | Recommended |
|--------|---------|-------------|
| Complexity | High (5 methods) | Low (1 method) |
| Security | Medium (non-expiring tokens) | High (JWT, expiring) |
| Postman Support | ❌ Broken | ✓ Works |
| Code Maintenance | Difficult | Easy |
| Developer UX | Confusing | Clear |
| Standards Compliant | Partial | Full (OAuth2) |

**Recommendation**: Implement the permanent fix. It's worth the effort!

