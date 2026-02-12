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
- Implement a BFF (backend-for-frontend) to do token exchanges and store refresh tokens securely in HTTP-only cookies; the Angular app talks only to BFF.
- Use an OIDC client library on DRF side to introspect tokens with provider token introspection endpoint instead of validating JWT locally.
- Implement role & scope mapping from token claims to Django permissions/groups.

---

## 10. Useful references
- OIDC Discovery: `/.well-known/openid-configuration/`
- JWKS endpoint: `/api/oidc/jwks/` or provider JWKS URL
- OAuth2 Authorization Code + PKCE: RFC 7636
- Libraries: `angular-oauth2-oidc`, `python-jose`, `PyJWT`

---

If you want, I can:
- Produce the exact DRF `SSOJWTAuthentication` file tailored to your DRF project's import paths and settings names.
- Provide an Angular example repo snippet using `angular-oauth2-oidc` with callback handling and an HTTP interceptor.
- Create a quick test script to validate tokens against your running SSO instance.

Which of those would you like next?