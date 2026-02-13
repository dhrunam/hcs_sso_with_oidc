# Integrating HCS SSO (OAuth2/OIDC) with an Angular Frontend and DRF Backend

This guide explains how to integrate the unified HCS SSO (OAuth2 + OIDC, JWT access tokens) with an Angular single-page app (SPA) and a Django REST Framework (DRF) API that uses PostgreSQL and references the Django `User` table via `user_id` foreign keys. The goal: minimal changes in the DRF project while keeping security and standards.

Summary approach (minimal DRF change):
- Use OAuth2 Authorization Code flow with PKCE for the Angular frontend.
- Angular obtains `access_token` (JWT) and sends `Authorization: Bearer <token>` to DRF.
- Add a compact DRF authentication class that verifies JWTs (via provider JWKS), maps claims to a Django `User` instance (by `sub`, `email`, or `preferred_username`), and sets `request.user` so existing models/foreign keys (user_id) work unchanged.
- Optionally create a lightweight provisioning step to create a Django user on first successful JWT validation.

---

## 1. Register the Angular client in the SSO provider (Django admin)
1. Open Django admin: `/admin/oauth2_provider/application/add/`.
2. Create an Application:
   - Name: `Angular SPA`
   - Client ID: (auto or custom)
   - Client Type: `Public`
   - Authorization Grant Type: `Authorization code`
   - Redirect URIs: `https://your-frontend.example.com/callback` (and `http://localhost:4200/callback` for dev)
   - Skip Authorization: *optional* (not recommended for production)
3. Ensure the app supports PKCE (provider setting `PKCE_REQUIRED=True` is enabled in sso/settings.py)

Notes: For local testing you can use `http://localhost:4200` redirect URIs. Keep the client public (no client_secret stored in the browser).

---

## 2. Angular frontend: Authorization Code + PKCE
Use a mature library to save work. Recommended: `angular-oauth2-oidc`.

Install:
```bash
npm i angular-oauth2-oidc
```

Example minimal configuration (in `app.module.ts` / auth service):
```ts
import { AuthConfig, OAuthService } from 'angular-oauth2-oidc';

const authConfig: AuthConfig = {
  issuer: 'http://localhost:8000',
  redirectUri: window.location.origin + '/callback',
  clientId: 'ANGULAR_CLIENT_ID',
  responseType: 'code',
  scope: 'openid profile email',
  showDebugInformation: false,
  strictDiscoveryDocumentValidation: false,
  requireHttps: false, // set true in production
  oidc: true,
  silentRefreshRedirectUri: window.location.origin + '/silent-refresh.html',
  useSilentRefresh: false, // optional; choose approach
  disablePKCE: false,
};

// In app start
oauthService.configure(authConfig);
oauthService.loadDiscoveryDocumentAndTryLogin();
```

HTTP Interceptor: send Authorization header for API calls
```ts
import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler } from '@angular/common/http';
import { OAuthService } from 'angular-oauth2-oidc';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private oauth: OAuthService) {}
  intercept(req: HttpRequest<any>, next: HttpHandler) {
    const token = this.oauth.getAccessToken();
    if (token) {
      const cloned = req.clone({ setHeaders: { Authorization: `Bearer ${token}` } });
      return next.handle(cloned);
    }
    return next.handle(req);
  }
}
```

Remember:
- Use Authorization Code + PKCE for SPAs. Do not store tokens in localStorage with long lifetimes in production.
- For refresh, prefer silent refresh (iframe) or short-lived tokens with re-auth; avoid storing refresh_token in browser unless using secure cookies via a backend.

---

## 3. DRF backend: minimal changes to accept SSO JWTs
Goal: DRF should accept Bearer JWTs from the SSO and set request.user as the Django user instance that existing models reference.

High-level steps:
1. Install dependencies on the DRF project:
   - `python-jose[cryptography]` or `PyJWT` + `cryptography`
   - `requests` (to fetch JWKS)

```bash
pip install python-jose[cryptography] requests
```

2. Add a compact `JWTAuthentication` class (custom DRF auth) that:
   - Reads `Authorization: Bearer <token>` header
   - Fetches & caches provider JWKS from `/.well-known/jwks.json` or `/api/oidc/jwks/`
   - Verifies signature and standard claims (`exp`, `aud`) using RS256
   - Extracts an identity claim (`sub`, `email`, or `preferred_username`)
   - Looks up Django `User` by id (if `sub` is user id) or by `email`; if not found, optionally auto-provision a user
   - Returns authenticated `(user, token)` pair to DRF

3. Configure DRF `REST_FRAMEWORK` setting to use the custom authentication class as first option.

### Minimal example (place in DRF project, e.g. `project/apps/authentication.py`)

```python
# authentication.py
import time
import requests
from jose import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import authentication, exceptions

User = get_user_model()

JWKS_URL = settings.SSO_JWKS_URI  # e.g. 'http://sso.example.com/api/oidc/jwks/'
JWKS_CACHE = {'keys': None, 'fetched_at': 0}
JWKS_CACHE_TTL = 60 * 60  # 1 hour

def get_jwks():
    now = time.time()
    if not JWKS_CACHE['keys'] or now - JWKS_CACHE['fetched_at'] > JWKS_CACHE_TTL:
        r = requests.get(JWKS_URL, timeout=5)
        r.raise_for_status()
        JWKS_CACHE['keys'] = r.json()
        JWKS_CACHE['fetched_at'] = now
    return JWKS_CACHE['keys']

class SSOJWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth = authentication.get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'bearer':
            return None
        if len(auth) == 1:
            raise exceptions.AuthenticationFailed('Invalid token header. No credentials provided.')
        token = auth[1].decode('utf-8')

        jwks = get_jwks()
        try:
            # You can pass jwks directly to jose.jwt.decode using the keys parameter
            claims = jwt.decode(token, jwks, algorithms=['RS256'], audience=settings.SSO_EXPECTED_AUDIENCE)
        except Exception as exc:
            raise exceptions.AuthenticationFailed(f'Token validation error: {exc}')

        # Map claims to a user
        sub = claims.get('sub')
        email = claims.get('email')

        user = None
        # Prefer numeric sub mapping to user_id if your provider issues user id as sub
        if sub and sub.isdigit():
            try:
                user = User.objects.get(pk=int(sub))
            except User.DoesNotExist:
                user = None

        if user is None and email:
            user = User.objects.filter(email__iexact=email).first()

        # Optionally auto-provision user if not found (keeps minimal DB changes)
        if user is None:
            user = User.objects.create_user(username=email or f'user_{sub}', email=email or '', password=None)

        # Optionally update user profile fields from claims
        # user.first_name = claims.get('given_name', user.first_name)
        # user.last_name = claims.get('family_name', user.last_name)
        # user.save()

        return (user, token)
```

> Notes:
> - `python-jose` supports passing JWKS directly to `jwt.decode`.
> - `SSO_EXPECTED_AUDIENCE` should be the client id or audience your API expects.

### DRF settings change (`settings.py` of DRF project)
```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'yourapp.authentication.SSOJWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
}

# SSO config
SSO_JWKS_URI = 'http://sso-host/.well-known/jwks.json'  # or http://localhost:8000/api/oidc/jwks/
SSO_EXPECTED_AUDIENCE = 'postman-client'  # or the client ID you expect
```

This keeps existing permission checks & view code intact because `request.user` becomes a standard Django `User` instance and your existing models referencing `user_id` will continue to work.

---

## 4. Database & user_id mapping notes (minimal-change options)

Cases to consider:

A. **DRF shares same Django database (same `auth_user` table)**
- Best case. When the Authentication class returns a `User` from the same table, no DB schema changes are needed; foreign keys referencing `user_id` still resolve.
- Ensure `sub` claim equals the Django `User.id` (preferable). If provider `sub` is not numeric, match by `email` or `username`.

B. **DRF uses separate DB but references user_id foreign keys**
- This is unusual (cross-DB foreign keys impossible). If so, you must either:
  - Move the user table to a shared DB, or
  - Maintain a mapping table (local user table with `sso_sub` and local id) and adapt the DRF models to refer to local user PK. That is not "minimal change".

C. **Provider `sub` is not user id**
- Use `email` or `preferred_username` claims to look up the Django user.
- If your user records lack email, add an email field or maintain mapping on first login (auto-provision user and store mapping to `sub`).

Auto-provisioning approach (minimal code):
- When token validated and no local user found, create a `User` record using `email` or `sub` as `username`. This keeps existing FK relationships functional for new sessions.
- Consider adding a short script to back-populate users for existing data if needed.

---

## 5. Security considerations & recommendations
- Use HTTPS in production; do not set `requireHttps=false` in Angular for production.
- Do not persist refresh tokens in the browser. If long sessions are required, use a backend-for-frontend (BFF) pattern or silent refresh.
- Validate `aud` (audience), `iss` (issuer) and `exp` (expiry) claims on the DRF side.
- Cache JWKS and re-fetch on key id (kid) mismatch or TTL expiry.
- Rotate keys on the SSO provider and verify via JWKS endpoint.
- Consider enforcing `email_verified` if provided by social providers before provisioning.

---

## 6. Testing checklist (manual)
- [ ] Register Angular client and set redirect URIs.
- [ ] Run Angular app and initiate login; confirm redirect to SSO and redirect back with code.
- [ ] Ensure PKCE values computed and code exchanged at SSO; Angular now has access token.
- [ ] Call DRF API endpoint with `Authorization: Bearer <access_token>`; expect 200 and `request.user` populated.
- [ ] Test user mapping: if user exists by id/email it should be used; otherwise a new user gets auto-created if provisioning enabled.
- [ ] Validate token expiry and refresh behavior.
- [ ] Check JWKS rotation handling by rotating keys on the provider (if feasible in staging).

---

## 7. Troubleshooting
- 401 from DRF: confirm Authorization header present and token valid via `jwt.io` or provider `/introspect` endpoint.
- Signature verification errors: check JWKS URL and cached keys; verify `kid` handling.
- user not found: check which claim you are mapping (`sub`, `email`) and confirm the provider issues it.
- Cross-DB FK errors: confirm DRF is using same `auth_user` table or implement mapping.

---

## 8. Example minimal changes summary (for DRF repo)
1. Install `python-jose` and `requests`.
2. Add `authentication.py` (SSOJWTAuthentication) to the DRF project.
3. Add `SSO_JWKS_URI` and `SSO_EXPECTED_AUDIENCE` to `settings.py`.
4. Configure `REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES']` to include the new auth class.
5. Optionally enable auto-provisioning in `SSOJWTAuthentication`.
6. Run tests and verify `request.user` is set and `user_id` foreign keys still work.

---

## 9. Further integration options (if you can accept more changes)

### Option A: Backend-for-Frontend (BFF) Pattern

The **Backend-for-Frontend** (BFF) pattern is a security best practice where a backend layer handles OAuth2 token exchange on behalf of the frontend. This keeps sensitive operations (code exchange, refresh tokens) server-side and out of the browser.

#### Why BFF?
- **Security**: Refresh tokens stored in HTTP-only cookies, not accessible to JavaScript
- **Token Exchange**: Authorization code is exchanged server-to-server, not in browser
- **Simplified Frontend**: Angular doesn't need to handle code exchange or token refresh logic
- **Centralized Control**: Token lifecycle managed in one place

#### BFF Endpoints

**1. Login endpoint**
```
POST /api/auth/login/sso
Content-Type: application/json

{
  "authorization_code": "abc123...",
  "code_verifier": "xyz789...",  // PKCE code_verifier from Angular
  "redirect_uri": "https://app.example.com/callback"
}

Response 200:
{
  "access_token": "eyJ...",
  "expires_in": 3600,
  "token_type": "Bearer"
}

Set-Cookie: refresh_token=refresh_abc...; HttpOnly; Secure; SameSite=Strict
```

**2. Refresh endpoint**
```
POST /api/auth/refresh/
No body; refresh_token automatically sent via cookies

Response 200:
{
  "access_token": "eyJ...(new)",
  "expires_in": 3600,
  "token_type": "Bearer"
}

Set-Cookie: refresh_token=refresh_new...; HttpOnly; Secure; SameSite=Strict
```

**3. Logout endpoint**
```
POST /api/auth/logout/
Optional: revokes token at provider

Response 200:
{
  "message": "Logged out successfully"
}

Set-Cookie: refresh_token=; Max-Age=0  (clear cookie)
```

#### Implementation

File: [apps/api/bff.py](apps/api/bff.py) (created)

The BFF module provides:
- `BFFLoginView` - Exchange authorization code for tokens
- `BFFTokenRefreshView` - Refresh access token using refresh_token from cookies
- `BFFLogoutView` - Logout and optionally revoke tokens
- `set_refresh_token_cookie()` - Secure HTTP-only cookie management
- `BFFAuthViewSet` - DRF ViewSet-based alternative

Required settings:
```python
# settings.py
SSO_TOKEN_URL = 'http://sso.example.com/o/token/'
BFF_CLIENT_ID = 'your-bff-client-id'  # Must be registered with client_secret
BFF_CLIENT_SECRET = 'your-bff-client-secret'
SECURE_COOKIE_SECURE = True  # Set False for local dev with HTTP
SECURE_COOKIE_SAMESITE = 'Strict'
```

URL routing:
```python
# apps/api/urls.py or sso/urls.py
from apps.api.bff import BFFLoginView, BFFTokenRefreshView, BFFLogoutView

urlpatterns = [
    path('api/auth/login/sso/', BFFLoginView.as_view(), name='bff-login'),
    path('api/auth/refresh/', BFFTokenRefreshView.as_view(), name='bff-refresh'),
    path('api/auth/logout/', BFFLogoutView.as_view(), name='bff-logout'),
]
```

#### Angular frontend changes

```typescript
// auth.service.ts
import { HttpClient, HttpClientModule } from '@angular/common/http';

@Injectable({ providedIn: 'root' })
export class AuthService {
  constructor(private http: HttpClient) {}
  
  // Step 1: Angular starts OAuth flow, gets authorization code
  // (using pkce library to generate code_challenge, code_verifier)
  
  loginWithSSO(authCode: string, codeVerifier: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>('/api/auth/login/sso/', {
      authorization_code: authCode,
      code_verifier: codeVerifier,
      redirect_uri: window.location.origin + '/callback'
    });
  }
  
  // Refresh token automatically via cookies (no need to handle in Angular)
  refreshToken(): Observable<TokenResponse> {
    return this.http.post<TokenResponse>('/api/auth/refresh/', {});
  }
  
  logout(): Observable<any> {
    return this.http.post('/api/auth/logout/', {});
  }
}

// HTTP Interceptor remains simple: add Authorization header
@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private auth: AuthService) {}
  
  intercept(req: HttpRequest<any>, next: HttpHandler) {
    const token = this.auth.getAccessToken();
    if (token) {
      req = req.clone({
        setHeaders: { Authorization: `Bearer ${token}` }
      });
    }
    return next.handle(req);
  }
}
```

#### Benefits
- Refresh tokens never exposed to JavaScript
- No JWKS caching needed in browser
- Simpler Angular code
- Centralized token management
- Cross-origin friendly (same-site cookies)

---

### Option B: Token Introspection Authentication

Instead of validating JWTs locally by fetching JWKS, use the provider's **token introspection endpoint** to validate tokens. This gives you immediate revocation support and simplified key rotation.

#### How it works
```
Browser/Angular -> Authorization: Bearer <token> -> DRF
DRF -> POST /o/introspect/ with token -> SSO Provider
SSO Provider -> { "active": true, "scope": "openid profile", "sub": "user_123", ... }
DRF -> Validates, maps token claims to Django User -> Allows request
```

#### Advantages
- Immediate token revocation (no cache delay)
- No need to fetch/cache JWKS
- Single source of truth at provider
- Simplified key rotation

#### Tradeoffs
- Network call per request (50-200ms latency)
- Provider introspection endpoint must be available
- Requires caching to avoid overwhelming provider

#### Implementation

File: [apps/api/authentication_introspection.py](apps/api/authentication_introspection.py) (created)

The module provides:
- `OIDCTokenIntrospectionAuthentication` - DRF auth class using introspection
- `TokenIntrospectionCache` - Caches introspection results with TTL
- `IntrospectionCacheInvalidationMixin` - For views that need to invalidate cache

Configuration:
```python
# settings.py
SSO_INTROSPECTION_URL = 'http://sso.example.com/o/introspect/'
SSO_CLIENT_ID = 'your-client-id'
SSO_CLIENT_SECRET = 'your-client-secret'
TOKEN_INTROSPECTION_CACHE_TTL = 300  # Cache for 5 minutes
SSO_AUTO_PROVISION_USER = False  # Set True to auto-create users from claims

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'apps.api.authentication_introspection.OIDCTokenIntrospectionAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
}
```

#### Usage in views
```python
from rest_framework.views import APIView
from rest_framework.response import Response

class MyView(APIView):
    def get(self, request):
        # request.user is authenticated Django User
        # request.token_claims contains introspection result
        # request.token_scopes contains parsed scopes
        
        scopes = request.token_scopes  # ['openid', 'profile', 'email']
        claims = request.token_claims  # Full introspection response
        
        return Response({'message': 'Hello ' + request.user.username})
```

#### Caching strategy

The implementation caches introspection results for 5 minutes (configurable). This balances:
- **Latency**: 5-min cache avoids per-request network call
- **Revocation**: Recent revocations take up to 5 minutes to take effect
- **Load**: Dramatically reduces load on introspection endpoint

For logout/revocation flows, invalidate the cache:
```python
from apps.api.authentication_introspection import TokenIntrospectionCache

def logout_view(request):
    # Clear this token from cache so next request gets fresh introspection
    token = request.META.get('HTTP_AUTHORIZATION', '').replace('Bearer ', '')
    cache_mgr = TokenIntrospectionCache()
    cache_mgr.invalidate(token)
    
    return Response({'message': 'Logged out'})
```

#### Comparing JWT validation vs Introspection

| Aspect | JWT (JWKS) | Introspection |
|--------|-----------|---------------|
| Revocation | Delayed (cache TTL) | Immediate |
| Latency | <1ms (local) | 50-200ms (network) |
| Key rotation | Automatic (JWKS) | Automatic |
| Network calls | Only JWKS fetch | Per request |
| Best for | High throughput | Security-first, lower QPS |

---

### Option C: Role & Scope Mapping to Django Permissions/Groups

Map OAuth2/OIDC **scopes** and **roles** claims to Django **Groups** and **Permissions**, enabling fine-grained access control based on token claims.

#### How it works
```
Token claims: { "scope": "api:read api:write", "roles": ["admin", "editor"] }
                ↓
Sync to Django: 
  - Add user to "Administrators" and "Editors" groups
  - Grant permissions: view_user, add_user, change_user, etc.
                ↓
DRF views check: @require_scope('api:write') or permission_classes=[ScopePermission]
```

#### Implementation

File: [apps/api/permissions_mapping.py](apps/api/permissions_mapping.py) (created)

The module provides:
- `ScopePermissionMapping` - Configurable scope-to-permission mapping
- `map_token_claims_to_groups()` - Sync roles → Django groups
- `sync_permissions_from_token_scopes()` - Sync scopes → Django permissions
- `ScopePermission` - DRF permission class checking scopes
- `RolePermission` - DRF permission class checking groups
- `@scope_required()` decorator - Enforce scopes on function views
- `@role_required()` decorator - Enforce roles on function views

#### Configuration

```python
# settings.py

SCOPE_TO_PERMISSION_MAP = {
    'api:read': [
        'view_user',
        'view_userprofile',
        'view_order',
    ],
    'api:write': [
        'add_user',
        'change_user',
        'add_userprofile',
        'change_userprofile',
        'add_order',
        'change_order',
    ],
    'admin': [
        'delete_user',
        'delete_userprofile',
        'delete_order',
    ],
}

ROLE_TO_GROUP_MAP = {
    'admin': 'Administrators',
    'editor': 'Editors',
    'viewer': 'Viewers',
}
```

#### Usage in authentication class

Add to your JWT or introspection authentication class:

```python
from apps.api.authentication_introspection import OIDCTokenIntrospectionAuthentication
from apps.api.permissions_mapping import map_token_claims_to_groups, sync_permissions_from_token_scopes

class OIDCTokenIntrospectionAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        user, token = super().authenticate(request)
        claims = introspect_token(token)
        
        # Map roles to groups
        map_token_claims_to_groups(user, claims, sync=True)
        
        # Map scopes to permissions
        scopes = claims.get('scope', '').split()
        sync_permissions_from_token_scopes(user, scopes, sync=True)
        
        return (user, token)
```

#### Using scope-based permissions in views

**Class-based views:**
```python
from rest_framework.views import APIView
from apps.api.permissions_mapping import ScopePermission

class OrderListView(APIView):
    permission_classes = [ScopePermission]
    required_scopes = ['api:read']  # User must have 'api:read' scope
    
    def get(self, request):
        return Response({'orders': [...]})

class OrderCreateView(APIView):
    permission_classes = [ScopePermission]
    required_scopes = ['api:write']  # User must have 'api:write' scope
    
    def post(self, request):
        # Create order
        return Response({'id': 123})
```

**ViewSet with scope checking:**
```python
from rest_framework.viewsets import ModelViewSet
from apps.api.permissions_mapping import ScopePermission

class UserViewSet(ModelViewSet):
    permission_classes = [ScopePermission]
    
    def get_required_scopes(self):
        """Return required scopes based on action."""
        if self.action in ['list', 'retrieve']:
            return ['api:read']
        elif self.action in ['create', 'update', 'partial_update']:
            return ['api:write']
        elif self.action == 'destroy':
            return ['admin']
        return []
    
    def get_permissions(self):
        """Dynamically set required_scopes."""
        permission_classes = self.permission_classes
        if issubclass(permission_classes[0], ScopePermission):
            for perm_class in permission_classes:
                perm_class.required_scopes = self.get_required_scopes()
        return [perm() for perm in permission_classes]
```

**Function-based views with decorators:**
```python
from rest_framework.decorators import api_view
from apps.api.permissions_mapping import scope_required, role_required

@api_view(['GET'])
@scope_required('api:read')
def order_list(request):
    return Response({'orders': [...]})

@api_view(['POST'])
@scope_required('api:write')
def create_order(request):
    return Response({'id': 123})

@api_view(['DELETE'])
@role_required('Administrators')
def delete_user(request, user_id):
    return Response({'deleted': True})
```

#### Group-based permissions in views

Use Django's group-based permission system:

```python
from django.contrib.auth.decorators import permission_required
from apps.api.permissions_mapping import RolePermission

class AdminView(APIView):
    permission_classes = [RolePermission]
    required_roles = ['Administrators']  # Must be in 'Administrators' group
    
    def post(self, request):
        # Admin-only action
        return Response({'result': 'success'})

# Or in function views
@api_view(['POST'])
@role_required('Administrators')
def admin_action(request):
    return Response({'result': 'success'})
```

#### Example: Complete token claim sync in authentication

```python
# apps/api/authentication.py
from rest_framework import authentication, exceptions
from apps.api.permissions_mapping import (
    map_token_claims_to_groups,
    sync_permissions_from_token_scopes,
)

class FullSSOAuthentication(authentication.BaseAuthentication):
    """Complete OIDC authentication with role/scope mapping."""
    
    def authenticate(self, request):
        auth = authentication.get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'bearer':
            return None
        
        token = auth[1].decode('utf-8')
        
        # Validate token and get claims
        claims = validate_jwt(token)  # or introspect_token(token)
        
        # Get or create user
        user = self._get_or_create_user(claims)
        
        # Sync group membership from roles
        roles_added, roles_removed = map_token_claims_to_groups(user, claims)
        logger.debug(f"User {user.id}: added groups {roles_added}, removed {roles_removed}")
        
        # Sync permissions from scopes
        scopes = claims.get('scope', '').split()
        perms_added, perms_removed = sync_permissions_from_token_scopes(user, scopes)
        logger.debug(f"User {user.id}: added perms {perms_added}, removed {perms_removed}")
        
        # Store claims in request for later use
        request.token_claims = claims
        request.token_scopes = scopes
        
        return (user, token)
    
    def _get_or_create_user(self, claims):
        # Implement user lookup/creation logic
        ...
```

#### Testing scope/role enforcement

```python
# tests.py
from django.test import TestCase
from rest_framework.test import APIClient
from django.contrib.auth.models import Group, User

class ScopePermissionTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user('testuser')
        self.admin_group = Group.objects.create(name='Administrators')
    
    def test_scope_permission_required(self):
        """Test that scope_required decorator enforces scopes."""
        # Without scope
        response = self.client.get('/api/orders/')
        self.assertEqual(response.status_code, 403)  # Forbidden
        
        # With scope in request
        self.client.request(headers={
            'Authorization': 'Bearer token_with_api:read'
        })
        response = self.client.get('/api/orders/')
        self.assertEqual(response.status_code, 200)  # OK
    
    def test_role_permission_required(self):
        """Test that role_required decorator enforces group membership."""
        # Without role
        response = self.client.get('/api/admin/')
        self.assertEqual(response.status_code, 403)
        
        # With role
        self.user.groups.add(self.admin_group)
        response = self.client.get('/api/admin/')
        self.assertEqual(response.status_code, 200)
```

---

---

## 10. Useful references
- OIDC Discovery: `/.well-known/openid-configuration/`
- JWKS endpoint: `/api/oidc/jwks/` or provider JWKS URL
- OAuth2 Authorization Code + PKCE: RFC 7636
- OAuth2 Token Introspection: RFC 7662
- Libraries: `angular-oauth2-oidc`, `python-jose`, `PyJWT`
- BFF Pattern: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps
- Django Groups & Permissions: https://docs.djangoproject.com/en/stable/topics/auth/

---

## 11. Implementation Files

Three new Python modules have been created to support advanced integration:

1. **[apps/api/bff.py](apps/api/bff.py)** - Backend-for-Frontend implementation
   - `BFFLoginView` - OAuth2 authorization code exchange
   - `BFFTokenRefreshView` - Token refresh using HTTP-only cookies
   - `BFFLogoutView` - Logout and token revocation
   - `BFFAuthViewSet` - DRF ViewSet-based alternative

2. **[apps/api/authentication_introspection.py](apps/api/authentication_introspection.py)** - Token introspection auth class
   - `OIDCTokenIntrospectionAuthentication` - DRF authentication using provider introspection
   - `TokenIntrospectionCache` - Caching with TTL for performance
   - `IntrospectionCacheInvalidationMixin` - Invalidate cache on logout

3. **[apps/api/permissions_mapping.py](apps/api/permissions_mapping.py)** - Role/scope to permissions mapping
   - `ScopePermissionMapping` - Configurable mapping rules
   - `map_token_claims_to_groups()` - Sync roles → Django groups
   - `sync_permissions_from_token_scopes()` - Sync scopes → Django permissions
   - `ScopePermission` - DRF permission class for scope checking
   - `RolePermission` - DRF permission class for group checking
   - `@scope_required()` - Decorator for function-based views
   - `@role_required()` - Decorator for group-based views

---

## 12. Quick Start Checklist for Each Option

### BFF Pattern
- [ ] Register BFF client in admin (must have client_secret)
- [ ] Configure SSO_TOKEN_URL, BFF_CLIENT_ID, BFF_CLIENT_SECRET in settings
- [ ] Add BFF views to urls.py
- [ ] Test: POST to `/api/auth/login/sso/` with authorization_code
- [ ] Verify refresh_token in response cookies (HttpOnly, Secure)
- [ ] Test refresh and logout endpoints

### Token Introspection
- [ ] Confirm SSO provider has introspection endpoint
- [ ] Install: `pip install python-jose requests`
- [ ] Configure SSO_INTROSPECTION_URL, SSO_CLIENT_ID, SSO_CLIENT_SECRET
- [ ] Update REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES'] to use OIDCTokenIntrospectionAuthentication
- [ ] Test: Send Bearer token to DRF endpoint
- [ ] Verify request.token_claims and request.token_scopes populated
- [ ] Configure cache TTL (default 5 minutes)

### Role/Scope Mapping
- [ ] Configure SCOPE_TO_PERMISSION_MAP in settings
- [ ] Configure ROLE_TO_GROUP_MAP in settings
- [ ] Add scope/role mapping calls to authentication class
- [ ] Use @scope_required() or ScopePermission in views
- [ ] Test: Verify groups and permissions synced from token claims
- [ ] Create Django groups to match ROLE_TO_GROUP_MAP values

---

## 13. Troubleshooting Advanced Options

### BFF Issues
- **403 Forbidden on login**: Check redirect_uri matches registered URI
- **Refresh returns 401**: Ensure refresh_token cookie is being sent; check HttpOnly/Secure settings
- **PKCE validation failed**: Verify code_verifier matches PKCE flow in Angular

### Introspection Issues
- **401 Unauthorized**: Token may be expired or revoked; check introspection response
- **High latency**: Increase TOKEN_INTROSPECTION_CACHE_TTL (tradeoff with revocation latency)
- **Connection refused**: Verify SSO_INTROSPECTION_URL is reachable and client credentials are correct

### Scope/Role Mapping Issues
- **Permissions not syncing**: Ensure scopes/roles present in token claims
- **Role names don't match**: Verify ROLE_TO_GROUP_MAP names match token claim values
- **Permission codenames not found**: Create Django permissions or check app_label in config

---

If you want, I can:
- Create settings.py configuration template for all three options
- Provide Angular integration examples for BFF endpoints
- Set up integration tests for authentication and permissions
- Create database migration for pre-provisioned groups and permissions

Which of those would you like next?