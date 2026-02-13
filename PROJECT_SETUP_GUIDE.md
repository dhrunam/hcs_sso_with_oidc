# Project Setup Guide: SSO + DRF Client + Angular

Complete setup instructions for integrating SSO (OAuth2/OIDC) with a separate DRF client and Angular frontend.

## Architecture Overview

You have **three separate projects**:

```
┌──────────────────┐
│ Angular Frontend │
│  localhost:4200  │
└────────┬─────────┘
         │ (1) Login request
         │ (2) Bearer token
         ▼
┌─────────────────────────────────┐
│ SSO Server (OAuth2 Provider)    │
│ localhost:8000                  │
│                                 │
│ • BFF endpoints                 │
│ • OAuth2 token management       │
│ • User authentication           │
└────────┬────────────────────────┘
         │ (3) Validate token
         │ (4) Introspect endpoint
         ▼
┌──────────────────────────┐
│ DRF Client API           │
│ (Separate project)       │
│                          │
│ • Protected endpoints    │
│ • Token validation       │
│ • Business logic         │
└──────────────────────────┘
```

---

## Part 1: SSO Server Setup (hcs_sso_with_oidc)

### Files Already Created ✅

All three Python modules are already in your SSO project:

```
apps/api/
├── bff.py                          ✅ Backend-for-Frontend (OAuth2 exchange)
├── authentication_introspection.py ✅ Token validation
└── permissions_mapping.py          ✅ Scope/role to permissions
```

### Step 1: Update sso/urls.py

Add BFF endpoints to your URL routing:

**File**: `sso/urls.py`

```python
from django.contrib import admin
from django.urls import path, include
from apps.api.bff import BFFLoginView, BFFTokenRefreshView, BFFLogoutView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    # ... your existing urls ...
    
    # ===== Add these BFF endpoints =====
    path('api/auth/login/sso/', BFFLoginView.as_view(), name='bff-login'),
    path('api/auth/refresh/', BFFTokenRefreshView.as_view(), name='bff-refresh'),
    path('api/auth/logout/', BFFLogoutView.as_view(), name='bff-logout'),
]
```

### Step 2: Update sso/settings.py

Add BFF configuration:

**File**: `sso/settings.py` (at the end of the file)

```python
# ===== BFF Configuration (Backend-for-Frontend) =====
# These settings handle token exchange for Angular frontend
# You must register a "Public" OAuth2 client in Django admin

BFF_CLIENT_ID = 'angular-spa-client'
BFF_CLIENT_SECRET = 'your-bff-client-secret'  # From Django admin

# OAuth2 token endpoint     
SSO_TOKEN_URL = 'http://localhost:8000/o/token/'
SSO_REVOKE_URL = 'http://localhost:8000/o/revoke/'  # Optional

# Cookie security settings
SECURE_COOKIE_SECURE = False  # Set True in production (HTTPS only)
SECURE_COOKIE_SAMESITE = 'Lax'  # Use 'Strict' in production

# ===== Token Introspection (for validating tokens) =====
# DRF client will use this to validate access tokens
SSO_INTROSPECTION_URL = 'http://localhost:8000/o/introspect/'
TOKEN_INTROSPECTION_CACHE_TTL = 300  # Cache for 5 minutes
```

### Step 3: Register OAuth2 Clients in Django Admin

Go to `http://localhost:8000/admin/oauth2_provider/application/`

**Client 1: Angular SPA (BFF Client)**
- Name: `Angular SPA`
- Client Type: `Public`
- Authorization Grant Type: `Authorization code`
- Redirect URIs: 
  - `http://localhost:4200/callback` (development)
  - `https://your-app.com/callback` (production)
- Skip Authorization: ✓ (recommended)
- PKCE required: ✓

**Client 2: DRF Client (for server-to-server)**
- Name: `DRF Client`
- Client Type: `Confidential`
- Authorization Grant Type: `Client credentials`
- Redirect URIs: (leave empty)
- Client ID: `your-drf-client-id`
- Client Secret: `your-drf-client-secret`

**Copy these values** → you'll need them in Step 2 of DRF Client setup

---

## Part 2: DRF Client Setup (Separate Project)

### Your DRF Project Structure

```
your-drf-project/
├── apps/
│   ├── api/
│   │   ├── authentication_introspection.py  ← Add here
│   │   ├── permissions_mapping.py           ← Add here (optional)
│   │   ├── views.py
│   │   └── ...
│   └── ...
├── manage.py
├── settings.py
└── requirements.txt
```

### Step 1: Copy Authentication Files from SSO Project

Copy these files from your SSO project to your DRF client project:

**From**: `/Users/dhrubajyotiborah/Documents/Projects/hcs_sso_with_oidc/apps/api/`
**To**: `your-drf-project/apps/api/`

Files to copy:
- `authentication_introspection.py` (required)
- `permissions_mapping.py` (optional, for fine-grained permissions)

### Step 2: Update DRF Project settings.py

Add OIDC/OAuth2 configuration:

**File**: `your-drf-project/settings.py`

```python
# ===== OAuth2/OIDC Token Validation =====
# This DRF project validates tokens from the SSO server
# Clients send: Authorization: Bearer <access_token>

SSO_INTROSPECTION_URL = 'http://localhost:8000/o/introspect/'  # SSO server
SSO_CLIENT_ID = 'your-drf-client-id'  # From Django admin (Client 2 above)
SSO_CLIENT_SECRET = 'your-drf-client-secret'  # From Django admin (Client 2 above)

# Performance optimization
TOKEN_INTROSPECTION_CACHE_TTL = 300  # Cache token validation for 5 minutes

# Auto-provision users from token claims (optional)
SSO_AUTO_PROVISION_USER = False  # Set True to auto-create users from SSO

# ===== DRF Authentication =====
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'apps.api.authentication_introspection.OIDCTokenIntrospectionAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
}

# ===== (Optional) Scope/Role Mapping =====
# Only if you want fine-grained access control
SCOPE_TO_PERMISSION_MAP = {
    'api:read': ['view_user', 'view_order'],
    'api:write': ['add_user', 'change_user', 'add_order', 'change_order'],
    'admin': ['delete_user', 'delete_order'],
}

ROLE_TO_GROUP_MAP = {
    'admin': 'Administrators',
    'editor': 'Editors',
}
```

### Step 3: Install Dependencies

In your DRF project, add to `requirements.txt`:

```
python-jose[cryptography]>=3.3.0
requests>=2.28.0
```

Then install:

```bash
pip install -r requirements.txt
```

### Step 4: Protect Your Endpoints

All endpoints now automatically require a valid Bearer token:

**File**: `your-drf-project/apps/api/views.py`

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

class UserListView(APIView):
    # Automatically requires: Authorization: Bearer <token>
    # If token is invalid or missing → 401 Unauthorized
    
    def get(self, request):
        # request.user is the Django User from SSO
        # request.token_claims contains all token data
        return Response({
            'message': f'Hello {request.user.username}',
            'user_id': request.user.id,
            'scopes': request.token_scopes,  # ['api:read', 'profile', ...]
        })

    def post(self, request):
        # Requires 'api:write' scope
        # request.token_claims['scope'] contains scopes
        if 'api:write' not in request.token_scopes:
            return Response(
                {'error': 'Missing required scope: api:write'},
                status=status.HTTP_403_FORBIDDEN
            )
        return Response({'created': True})
```

### Step 5: (Optional) Add Scope-Based Permissions

If you want fine-grained access control:

**File**: `your-drf-project/apps/api/views.py`

```python
from rest_framework.views import APIView
from apps.api.permissions_mapping import ScopePermission

class OrderListView(APIView):
    permission_classes = [ScopePermission]
    required_scopes = ['api:read']  # Only users with this scope
    
    def get(self, request):
        return Response({'orders': []})

class OrderCreateView(APIView):
    permission_classes = [ScopePermission]
    required_scopes = ['api:write']  # Only users with this scope
    
    def post(self, request):
        return Response({'id': 123})
```

---

## Part 3: Angular Frontend Setup

### Installation

```bash
npm install angular-oauth2-oidc
```

### Create Auth Service

**File**: `src/app/services/auth.service.ts`

```typescript
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private ssoServerUrl = 'http://localhost:8000';
  private accessToken: string | null = null;

  constructor(private http: HttpClient) {
    this.accessToken = localStorage.getItem('access_token');
  }

  /**
   * Step 1: User clicks "Login"
   * Generate PKCE challenge and redirect to SSO login
   */
  startLogin(): void {
    // Generate PKCE code_challenge and code_verifier
    const state = this.generateRandomString(32);
    const codeVerifier = this.generateRandomString(64);
    const codeChallenge = this.generateCodeChallenge(codeVerifier);

    // Store in session for callback
    sessionStorage.setItem('code_verifier', codeVerifier);
    sessionStorage.setItem('state', state);

    // Redirect to SSO login
    const params = new URLSearchParams({
      client_id: 'angular-spa-client',
      redirect_uri: `${window.location.origin}/callback`,
      response_type: 'code',
      scope: 'openid profile email',
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    window.location.href = `${this.ssoServerUrl}/o/authorize/?${params}`;
  }

  /**
   * Step 2: User logs in at SSO and is redirected back
   * Exchange authorization code for access token
   */
  handleCallback(code: string): Observable<any> {
    const codeVerifier = sessionStorage.getItem('code_verifier');
    if (!codeVerifier) throw new Error('Code verifier not found');

    return this.http.post(`${this.ssoServerUrl}/api/auth/login/sso/`, {
      authorization_code: code,
      code_verifier: codeVerifier,
      redirect_uri: `${window.location.origin}/callback`,
    });
  }

  /**
   * Step 3: Store the access token and use it for API calls
   */
  storeToken(response: any): void {
    this.accessToken = response.access_token;
    localStorage.setItem('access_token', this.accessToken);
  }

  /**
   * Step 4: Refresh the access token
   */
  refreshToken(): Observable<any> {
    return this.http.post(`${this.ssoServerUrl}/api/auth/refresh/`, {});
  }

  /**
   * Step 5: Logout
   */
  logout(): Observable<any> {
    return this.http.post(`${this.ssoServerUrl}/api/auth/logout/`, {});
  }

  /**
   * Get current access token
   */
  getAccessToken(): string | null {
    return this.accessToken;
  }

  // Utility functions
  private generateRandomString(length: number): string {
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  private generateCodeChallenge(codeVerifier: string): string {
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hash = crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode(...new Uint8Array(hash)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}
```

### Create HTTP Interceptor

**File**: `src/app/interceptors/auth.interceptor.ts`

```typescript
import { Injectable } from '@angular/core';
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpEvent,
} from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthService } from '../services/auth.service';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private auth: AuthService) {}

  intercept(
    req: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    const token = this.auth.getAccessToken();

    if (token) {
      // Add Authorization header with Bearer token
      const cloned = req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`,
        },
      });
      return next.handle(cloned);
    }

    return next.handle(req);
  }
}
```

### Register Interceptor in App Module

**File**: `src/app/app.module.ts`

```typescript
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { AuthInterceptor } from './interceptors/auth.interceptor';

@NgModule({
  declarations: [
    // ...
  ],
  imports: [
    BrowserModule,
    HttpClientModule,
    // ...
  ],
  providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true,
    },
  ],
  bootstrap: [AppComponent],
})
export class AppModule {}
```

### Create Callback Component

**File**: `src/app/components/callback/callback.component.ts`

```typescript
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-callback',
  template: '<p>Processing login...</p>',
})
export class CallbackComponent implements OnInit {
  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private auth: AuthService
  ) {}

  ngOnInit(): void {
    // Get authorization code from URL
    this.route.queryParams.subscribe((params) => {
      const code = params['code'];
      const state = params['state'];

      if (!code) {
        console.error('No authorization code in callback');
        this.router.navigate(['/login']);
        return;
      }

      // Exchange code for access token
      this.auth.handleCallback(code).subscribe({
        next: (response) => {
          this.auth.storeToken(response);
          this.router.navigate(['/dashboard']);
        },
        error: (error) => {
          console.error('Login failed:', error);
          this.router.navigate(['/login']);
        },
      });
    });
  }
}
```

### Update App Routing

**File**: `src/app/app-routing.module.ts`

```typescript
import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { CallbackComponent } from './components/callback/callback.component';
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { LoginComponent } from './components/login/login.component';

const routes: Routes = [
  { path: 'login', component: LoginComponent },
  { path: 'callback', component: CallbackComponent },
  { path: 'dashboard', component: DashboardComponent },
  { path: '', redirectTo: '/dashboard', pathMatch: 'full' },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
```

---

## Testing & Verification

### 1. Test SSO BFF Endpoints

```bash
# Test login endpoint
curl -X POST http://localhost:8000/api/auth/login/sso/ \
  -H "Content-Type: application/json" \
  -d '{
    "authorization_code": "abc123...",
    "code_verifier": "xyz789...",
    "redirect_uri": "http://localhost:4200/callback"
  }'

# Expected response:
# {
#   "access_token": "eyJ...",
#   "expires_in": 3600,
#   "token_type": "Bearer"
# }
# Set-Cookie: refresh_token=...; HttpOnly; Secure; SameSite=Lax
```

### 2. Test DRF Protected Endpoint

```bash
# Get access token first from SSO BFF
export TOKEN="eyJ..."

# Call DRF API with token
curl -X GET http://localhost:8001/api/users/ \
  -H "Authorization: Bearer $TOKEN"

# Expected: 200 OK with user data
# Without token: 401 Unauthorized
```

### 3. Test Angular Flow

1. Navigate to `http://localhost:4200/login`
2. Click "Login"
3. Should redirect to SSO login page
4. Login with SSO credentials
5. Should redirect back to `http://localhost:4200/callback`
6. Should store access token
7. Should redirect to dashboard
8. Dashboard can call DRF API with token

---

## Troubleshooting

### "Invalid Client" Error

- Check that you registered the OAuth2 client in Django admin
- Verify `BFF_CLIENT_ID` matches the client registered in admin
- Ensure `Redirect URIs` in admin matches the frontend URL

### "Token Validation Failed"

- Verify `SSO_INTROSPECTION_URL` in DRF settings points to SSO
- Check that `SSO_CLIENT_ID` and `SSO_CLIENT_SECRET` in DRF match the registered "DRF Client"
- Ensure token is not expired
- Check DRF logs for introspection errors

### "CORS Error"

Add CORS settings to SSO `settings.py`:

```python
INSTALLED_APPS = [
    # ...
    'corsheaders',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    # ...
]

CORS_ALLOWED_ORIGINS = [
    'http://localhost:4200',
    'http://localhost:3000',
]
```

### "Refresh Token Not in Cookie"

- Check `SECURE_COOKIE_SECURE = False` in SSO settings (for localhost)
- Browser must be configured to accept cookies
- Ensure CORS allows credentials: add to Angular HTTP client

```typescript
this.http.post(url, data, { withCredentials: true })
```

---

## Production Deployment Checklist

### SSO Server
- [ ] Set `SECURE_COOKIE_SECURE = True` (HTTPS required)
- [ ] Set `SECURE_COOKIE_SAMESITE = 'Strict'`
- [ ] Use strong `BFF_CLIENT_SECRET`
- [ ] Set `SSO_TOKEN_URL` to production domain
- [ ] Configure CORS for production domain
- [ ] Enable HTTPS certificate

### DRF Client
- [ ] Update `SSO_INTROSPECTION_URL` to production SSO domain
- [ ] Use strong `SSO_CLIENT_SECRET`
- [ ] Set `TOKEN_INTROSPECTION_CACHE_TTL` appropriately (5-10 min)
- [ ] Enable logging for debugging
- [ ] Configure firewall to allow introspection calls

### Angular Frontend
- [ ] Change `ssoServerUrl` to production domain
- [ ] Update `client_id` to production client
- [ ] Set `redirect_uri` to production URL
- [ ] Enable HTTPS

---

## Quick Reference

| Component | Endpoint | Purpose |
|-----------|----------|---------|
| SSO | `POST /api/auth/login/sso/` | Exchange code for token |
| SSO | `POST /api/auth/refresh/` | Refresh access token |
| SSO | `POST /api/auth/logout/` | Logout and clear tokens |
| SSO | `POST /o/introspect/` | Validate tokens (used by DRF) |
| DRF | `GET /api/users/` | Protected endpoint (requires token) |
| Angular | `/login` | Login page |
| Angular | `/callback` | OAuth2 callback handler |

---

## Additional Resources

- [INTEGRATE_ANGULAR_DRF.md](INTEGRATE_ANGULAR_DRF.md) - Detailed integration guide
- [django-oauth-toolkit docs](https://django-oauth-toolkit.readthedocs.io/)
- [Django REST Framework docs](https://www.django-rest-framework.org/)
- [OAuth 2.0 PKCE](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect](https://openid.net/connect/)
