# SSO OAuth2/OIDC Architecture Diagrams

## 1. High-Level OAuth 2.0 Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         COMPLETE OAUTH 2.0 FLOW                            │
└─────────────────────────────────────────────────────────────────────────────┘

┌────────────┐         ┌──────────────┐         ┌──────────────┐
│  External  │         │  HCS SSO     │         │    Social    │
│    App     │────────▶│  Server      │         │  Providers   │
│ (SPA/      │         │              │◀────────│ (Google,     │
│ Mobile)    │         │ ┌──────────┐ │         │  Facebook,   │
└────────────┘         │ │OAuth2    │ │         │  etc)        │
                       │ │Provider  │ │         └──────────────┘
                       │ └──────────┘ │
                       │              │
                       │ ┌──────────┐ │
                       │ │Auth      │ │
                       │ │Database  │ │
                       │ └──────────┘ │
                       └──────────────┘


STEP 1: Authorization Request
────────────────────────────────────────────────────────────────
External App → GET /o/authorize/
  ?client_id=YOUR_CLIENT_ID
  &redirect_uri=https://app.example.com/callback
  &response_type=code
  &scope=openid+profile+email
  &state=random_state_value
  &code_challenge=pkce_challenge


STEP 2: Check User Authentication
────────────────────────────────────────────────────────────────
User authenticated?
    │
    ├─ YES ──→ Continue to Step 4 (Scope Consent)
    │
    └─ NO ──→ Redirect to /login/


STEP 3A: Authentication Method Selection
────────────────────────────────────────────────────────────────
GET /login/

┌─────────────────────────────────────┐
│   Choose How to Sign In             │
├─────────────────────────────────────┤
│                                     │
│  ┌─────────────────────────────┐   │
│  │  🏢 HCS Account             │   │
│  │  Use organization creds     │   │
│  └─────────────────────────────┘   │
│              OR                     │
│  ┌─────────────────────────────┐   │
│  │  🔵 Google                  │   │
│  └─────────────────────────────┘   │
│  ┌─────────────────────────────┐   │
│  │  👤 Facebook                │   │
│  └─────────────────────────────┘   │
│  ┌─────────────────────────────┐   │
│  │  ⚡ Microsoft               │   │
│  └─────────────────────────────┘   │
│  ┌─────────────────────────────┐   │
│  │  🐱 GitHub                  │   │
│  └─────────────────────────────┘   │
│  ┌─────────────────────────────┐   │
│  │  💼 LinkedIn                │   │
│  └─────────────────────────────┘   │
│                                     │
└─────────────────────────────────────┘


STEP 3B (Path A): Organization Account Login
────────────────────────────────────────────────────────────────
GET /accounts/login/ (with next=/o/authorize/?...)

┌──────────────────────────┐
│  HCS Account Login       │
├──────────────────────────┤
│  Username: [          ]  │
│  Password: [          ]  │
│  ☑ Remember me           │
│           [Sign In]      │
│                          │
│  [Back to Login Options] │
└──────────────────────────┘

POST /accounts/login/
  ├─ Validate username & password
  ├─ Check User.objects.filter(username=...)
  ├─ Verify password (argon2/bcrypt)
  │
  ├─ IF VALID:
  │   ├─ Create session
  │   ├─ Call login(request, user)
  │   ├─ Log: "Organization login successful"
  │   └─ Redirect to 'next' parameter
  │       (back to /o/authorize/)
  │
  └─ IF INVALID:
      ├─ Show error message
      └─ Return to form


STEP 3B (Path B): Social Provider Login
────────────────────────────────────────────────────────────────
GET /social/login/google/ (or facebook, microsoft, etc)

  ├─ Redirect to Provider (e.g., Google OAuth URL)
  │
  ├─ User authenticates with Provider
  │
  ├─ Provider redirects to /social/complete/google/
  │
  ├─ django-social-auth processes response
  │   ├─ Validate provider token
  │   ├─ Extract user info
  │   ├─ Create/update User in database
  │   └─ Create session
  │
  └─ Redirect to next parameter
      (back to /o/authorize/)


STEP 4: Scope Consent
────────────────────────────────────────────────────────────────
GET /o/authorize/ (user now authenticated)

┌──────────────────────────────────────────┐
│  Authorize Access Request                │
├──────────────────────────────────────────┤
│                                          │
│  Your App wants to access:               │
│  ✓ Your basic profile (openid)           │
│  ✓ Your email address (email)            │
│  ✓ Your public profile (profile)         │
│                                          │
│           [Allow]  [Deny]                │
│                                          │
└──────────────────────────────────────────┘


STEP 5A: User Grants Permission
────────────────────────────────────────────────────────────────
POST /o/authorize/

  ├─ Validate scope request
  ├─ Check if user already approved
  ├─ Generate authorization code
  │   code = random(128-bit secure)
  │
  └─ Redirect to:
      redirect_uri?code=AUTH_CODE&state=SAME_STATE


STEP 5B: User Denies Permission
────────────────────────────────────────────────────────────────
POST /o/authorize/ (Deny)

  └─ Redirect to:
      redirect_uri?error=access_denied&state=SAME_STATE


STEP 6: External App Receives Code
────────────────────────────────────────────────────────────────
Browser redirects to:
  https://app.example.com/callback?code=AUTH_CODE&state=SAME_STATE

App's backend receives request:
  ├─ Validate state parameter
  ├─ Extract code
  └─ Continue to Step 7


STEP 7: Exchange Code for Tokens
────────────────────────────────────────────────────────────────
App Backend:
  POST /o/token/
    grant_type=authorization_code
    code=AUTH_CODE
    client_id=CLIENT_ID
    redirect_uri=REGISTERED_REDIRECT_URI
    code_verifier=PKCE_VERIFIER
    (client_secret if confidential client)

SSO Server validates:
  ├─ code exists and not expired
  ├─ code not already used
  ├─ redirect_uri matches
  ├─ client_id is valid
  ├─ PKCE verifier matches challenge
  └─ client authentication (if required)

Response:
  {
    "access_token": "eyJhbGciOiJSUzI1NiJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "abc123...",
    "id_token": "eyJhbGciOiJSUzI1NiJ9..."
  }


STEP 8: App Uses Tokens
────────────────────────────────────────────────────────────────
Access Token - For API calls:
  GET /api/oidc/userinfo/
    Authorization: Bearer ACCESS_TOKEN
  
  Response:
  {
    "sub": "1",
    "name": "John Doe",
    "email": "john@hcs.gov",
    "picture": "https://..."
  }

ID Token - JWT with user claims (decoded):
  {
    "iss": "http://localhost:8000",
    "sub": "1",
    "aud": "CLIENT_ID",
    "exp": 1234567890,
    "iat": 1234564290,
    "name": "John Doe",
    "email": "john@hcs.gov",
    "email_verified": true,
    "picture": "https://..."
  }

Refresh Token - For getting new access token:
  POST /o/token/
    grant_type=refresh_token
    refresh_token=REFRESH_TOKEN
    client_id=CLIENT_ID
  
  Response: New access_token


```

---

## 2. Organization Login Flow (Detailed)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│               ORGANIZATION (HCS) ACCOUNT LOGIN FLOW                         │
└─────────────────────────────────────────────────────────────────────────────┘


START: User clicks "HCS Account" at /login/
   │
   ▼
GET /accounts/login/?next=/o/authorize/?client_id=...

   │
   ▼
┌────────────────────────────────────┐
│  OrganizationLoginView             │
│  (apps/core/views.py)              │
│                                    │
│  GET request:                      │
│  - Render form template            │
│  - Pass 'next' to context          │
└────────────────────────────────────┘
   │
   ▼
Render: /templates/registration/login.html
   │
   ├─ Form fields:
   │   ├─ Username input
   │   ├─ Password input
   │   └─ Remember me checkbox
   │
   ├─ Hidden fields:
   │   └─ <input name="next" value="/o/authorize/?...">
   │
   └─ Error display (if previous submission failed)
   │
   ▼
User enters credentials and clicks "Sign In"

   │
   ▼
POST /accounts/login/ with:
  - username=user_input
  - password=user_input
  - next=/o/authorize/?...

   │
   ▼
┌────────────────────────────────────┐
│  OrganizationLoginView.form_valid()│
│                                    │
│  1. Get user from form             │
│     AuthenticationForm.get_user()  │
│                                    │
│  2. Call Django login()            │
│     login(request, user)           │
│     ├─ Create session              │
│     ├─ Set session cookie          │
│     └─ Mark user as authenticated  │
│                                    │
│  3. Get 'next' from form data      │
│     next_url = POST['next']        │
│                                    │
│  4. If next exists:                │
│     return HttpResponseRedirect    │
│            (next_url)              │
└────────────────────────────────────┘
   │
   ├─ IF CREDENTIALS INVALID:
   │   │
   │   ├─ AuthenticationForm validation fails
   │   ├─ form_invalid() called
   │   └─ Re-render form with error message
   │
   └─ IF CREDENTIALS VALID:
       │
       ▼
   Browser redirected to:
   /o/authorize/?client_id=...&redirect_uri=...&...
       │
       ▼
   OAuth2 Provider:
   - User is now authenticated
   - Show scope consent
   - User clicks "Allow"
   - Generate authorization code
   - Redirect to app with code
       │
       ▼
   ✓ SUCCESS


DATABASE FLOW:

    Username/Password
        │
        ▼
    ┌──────────────────────────┐
    │  Django Auth Backend     │
    │                          │
    │  ModelBackend processes: │
    │  1. Query User table:    │
    │     User.objects.get(    │
    │       username=username) │
    │                          │
    │  2. Check password:      │
    │     user.check_password()│
    │     (uses argon2/bcrypt) │
    │                          │
    │  3. Check is_active:     │
    │     user.is_active       │
    └──────────────────────────┘
        │
        ├─ User found and password matches
        │   and is_active = True
        │   └─ Return user object ✓
        │
        └─ Any check fails
            └─ Raise AuthenticationFailed ✗


SESSION CREATION:

    User authenticated ✓
        │
        ▼
    ┌──────────────────────────┐
    │  Django SessionBackend   │
    │                          │
    │  1. Create session data: │
    │     - _auth_user_id      │
    │     - _auth_user_backend │
    │     - _auth_user_hash    │
    └──────────────────────────┘
        │
        ▼
    ┌──────────────────────────┐
    │  Set session cookie:     │
    │  - sessionid=abc123...   │
    │  - HttpOnly (secure)     │
    │  - SameSite=Strict       │
    │  - Expires in 24 hours   │
    └──────────────────────────┘
        │
        ▼
    User has valid session ✓
    (Will pass is_authenticated check)


NEXT PARAMETER FLOW:

    1. User clicks "HCS Account" at /login/
       Template has link:
       <a href="/accounts/login/?next=/login/">
    
    2. Request arrives with:
       GET /accounts/login/?next=/login/...
    
    3. View extracts next:
       next_url = request.GET.get('next')
    
    4. Form renders hidden field:
       <input type="hidden" name="next" value="...">
    
    5. Form submitted with next:
       POST /accounts/login/
       Form data: { next: "/o/authorize/?..." }
    
    6. View extracts next from form:
       next_url = self.request.POST.get('next')
    
    7. If next exists, redirect:
       return HttpResponseRedirect(next_url)
       └─ Seamless redirect back to OAuth2!

```

---

## 3. Django Authentication Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DJANGO AUTHENTICATION STACK                              │
└─────────────────────────────────────────────────────────────────────────────┘


Request with Credentials
        │
        ▼
    ┌──────────────────────────────┐
    │  AuthenticationForm          │
    │  (from django.contrib.auth)  │
    │                              │
    │  Fields:                     │
    │  - username                  │
    │  - password                  │
    │  - (CSRF token)              │
    │                              │
    │  Validation:                 │
    │  - authenticate() called     │
    │  - Returns user or None      │
    └──────────────────────────────┘
        │
        ▼
    ┌──────────────────────────────┐
    │  AUTHENTICATION_BACKENDS     │
    │  (from settings.py)          │
    │                              │
    │  List of backends:           │
    │  1. ModelBackend (default)   │
    │     - Checks User table      │
    │     - Uses check_password()  │
    │                              │
    │  2. social_core backends     │
    │     - For social providers   │
    │                              │
    │  3. Custom backends          │
    │     - Can be added           │
    └──────────────────────────────┘
        │
        ▼
    ┌──────────────────────────────┐
    │  Each Backend:               │
    │                              │
    │  def authenticate(username,  │
    │                  password):  │
    │                              │
    │    1. Try to find user       │
    │    2. Check password         │
    │    3. Return user or None    │
    │                              │
    │  First backend to return     │
    │  user wins!                  │
    └──────────────────────────────┘
        │
        ├─ None returned
        │  └─ Try next backend
        │
        └─ User returned
            └─ Stop, use this user
                │
                ▼
            ┌──────────────────────┐
            │  login(request,      │
            │        user)         │
            │                      │
            │  1. Create session   │
            │  2. Set cookie       │
            │  3. Attach user to   │
            │     request object   │
            └──────────────────────┘
                │
                ▼
            ✓ User authenticated


USER MODEL:
────────────────────────────────────────────────────

    ┌─ django.contrib.auth.models.User
    │
    ├─ Fields:
    │  ├─ id (auto)
    │  ├─ username (unique)
    │  ├─ email
    │  ├─ password (hashed)
    │  ├─ first_name
    │  ├─ last_name
    │  ├─ is_active (default=True)
    │  ├─ is_staff (default=False)
    │  ├─ is_superuser (default=False)
    │  ├─ last_login
    │  └─ date_joined
    │
    ├─ Methods:
    │  ├─ check_password(pwd)
    │  │  └─ Uses argon2/bcrypt
    │  │
    │  ├─ set_password(pwd)
    │  │  └─ Hashes password
    │  │
    │  └─ is_authenticated
    │     └─ True if logged in
    │
    └─ Can be extended:
       └─ Custom user model with extra fields


PASSWORD HASHING:
────────────────────────────────────────────────────

    Raw Password: "TestPassword123!"
            │
            ▼
    ┌──────────────────────────┐
    │  PASSWORD_HASHERS        │
    │  (from settings.py)      │
    │                          │
    │  Default order:          │
    │  1. Argon2 (preferred)   │
    │  2. PBKDF2               │
    │  3. bcrypt               │
    │  4. scrypt               │
    └──────────────────────────┘
            │
            ▼
    Hash: argon2$argon2id$v=19$m=102400,t=2,p=8$J8w...
    
    (Can't reverse - one-way function)
            │
            ▼
    Stored in User.password field
            │
            ▼
    Later, check_password():
    - Hash input password with same settings
    - Compare hashes (constant-time)
    - Return True/False


SESSION MANAGEMENT:
────────────────────────────────────────────────────

    ┌──────────────────────────────┐
    │  Settings (settings.py)      │
    │                              │
    │  SESSION_COOKIE_AGE = 86400  │
    │  (24 hours)                  │
    │                              │
    │  SESSION_COOKIE_SECURE = ?   │
    │  (HTTPS only in production)  │
    │                              │
    │  SESSION_COOKIE_HTTPONLY =?  │
    │  (No JavaScript access)      │
    │                              │
    │  SESSION_COOKIE_SAMESITE =?  │
    │  (CSRF protection)           │
    └──────────────────────────────┘
            │
            ▼
    ┌──────────────────────────────┐
    │  Session Backend             │
    │  (default: database)         │
    │                              │
    │  Stores in:                  │
    │  - django_session table      │
    │  - OR cache                  │
    │  - OR signed cookies         │
    └──────────────────────────────┘
            │
            ▼
    Client receives cookie:
    Set-Cookie: sessionid=abc123xyz; Path=/; HttpOnly; Secure
            │
            ▼
    Browser sends with each request:
    Cookie: sessionid=abc123xyz
            │
            ▼
    Django middleware:
    - Loads session from backend
    - Attaches to request.session
    - Sets request.user
    ├─ If session valid:
    │  └─ User authenticated
    └─ If session invalid:
       └─ AnonymousUser

```

---

## 4. URL Routing

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          URL ROUTING FLOW                                   │
└─────────────────────────────────────────────────────────────────────────────┘


Incoming Request
    │
    ▼
Django URL Router
(sso/urls.py)
    │
    ├─ path('admin/', admin.site.urls)
    │
    ├─ path('accounts/', include('django.contrib.auth.urls'))
    │  └─ Includes: password_reset, password_change, etc.
    │
    ├─ path('o/', include('oauth2_provider.urls'))
    │  ├─ /o/authorize/
    │  ├─ /o/token/
    │  ├─ /o/revoke_token/
    │  └─ /o/introspect/
    │
    ├─ path('api/', include('apps.api.urls'))
    │
    ├─ path('api/users/', include('apps.users.urls'))
    │
    ├─ path('api/oidc/', include('apps.oidc.urls'))
    │  ├─ /api/oidc/userinfo/
    │  ├─ /api/oidc/jwks/
    │  └─ /api/oidc/token/introspect/
    │
    ├─ path('api/social/', include('apps.social.urls'))
    │
    ├─ path('social/', include('social_django.urls'))
    │  ├─ /social/login/<backend>/
    │  ├─ /social/complete/<backend>/
    │  └─ /social/disconnect/<backend>/
    │
    ├─ path('', TemplateView → 'index.html')
    │  └─ Homepage (/)
    │
    ├─ path('login/', TemplateView → 'login.html')
    │  └─ Authentication method selection (/login/)
    │
    ├─ path('accounts/login/', OrganizationLoginView)
    │  └─ Organization credential form (/accounts/login/)
    │
    ├─ path('accounts/profile/', TemplateView → 'profile.html')
    │  └─ User profile page (/accounts/profile/)
    │
    └─ path('.well-known/openid-configuration/', WellKnownConfigurationView)
       └─ OIDC discovery endpoint (/.well-known/openid-configuration/)


REQUEST MATCHING LOGIC:

    GET /accounts/login/
        │
        ├─ Matches 'accounts/' from django.contrib.auth.urls?
        │   └─ No (not in that namespace)
        │
        ├─ Matches 'o/'?
        │   └─ No
        │
        ├─ ... other paths ...
        │
        ├─ Matches 'accounts/login/'?
        │   └─ YES! ✓
        │
        ▼
    Django creates view instance:
    view = OrganizationLoginView.as_view()
        │
        ▼
    Calls view.dispatch(request)
        │
        ├─ if request.method == 'GET':
        │   └─ view.get() → render form
        │
        └─ if request.method == 'POST':
            └─ view.post() → validate form → form_valid() or form_invalid()


VIEW CLASS INHERITANCE:

    View (Django base)
        │
        └─ FormView
            │
            └─ LoginView (Django built-in)
                │
                └─ OrganizationLoginView (custom)
                    │
                    ├─ GET /accounts/login/
                    │   └─ Render form from template
                    │
                    └─ POST /accounts/login/
                        ├─ Bind data to form
                        ├─ Validate form
                        │
                        ├─ form_valid():
                        │   ├─ Get user from form
                        │   ├─ Call login()
                        │   ├─ Get 'next' parameter
                        │   └─ Redirect (with or without next)
                        │
                        └─ form_invalid():
                            └─ Re-render form with errors

```

---

## 5. OAuth2 Provider State Machine

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    OAUTH2 PROVIDER STATE MACHINE                            │
└─────────────────────────────────────────────────────────────────────────────┘


        ┌─────────────────────────────────────────────────────┐
        │  INITIAL STATE                                       │
        │  (Authorization request received)                    │
        └─────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌─────────────────────────────────────────────────────┐
        │  VALIDATE REQUEST                                    │
        │                                                      │
        │  ✓ client_id exists                                 │
        │  ✓ redirect_uri registered                          │
        │  ✓ response_type = "code"                           │
        │  ✓ scope valid                                      │
        │  ✓ state provided                                   │
        │  ✓ code_challenge valid (PKCE)                      │
        │  ✓ required fields present                          │
        └─────────────────────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
            ERROR                   VALID
                │                       │
                └─────────┬─────────────┘
                          ▼
        ┌─────────────────────────────────────────────────────┐
        │  CHECK USER AUTHENTICATION                          │
        │                                                      │
        │  Is user logged in?                                 │
        │  (request.user.is_authenticated)                    │
        └─────────────────────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
              NO                      YES
                │                       │
                ▼                       ▼
        ┌──────────────────┐    ┌──────────────────┐
        │ REDIRECT TO      │    │ SHOW SCOPE       │
        │ LOGIN_URL        │    │ CONSENT          │
        │ (/login/)        │    │                  │
        └──────────────────┘    └──────────────────┘
                │                       │
                ▼                       │
        User authentication:            │
        1. Sees /login/                 │
        2. Chooses org or social        │
        3. Provides credentials         │
        4. Gets session created         │
        5. Redirects back to            │
           /o/authorize/ (with 'next')  │
                │                       │
                └───────────┬───────────┘
                            ▼
        ┌─────────────────────────────────────────────────────┐
        │  SHOW SCOPE CONSENT SCREEN                          │
        │                                                      │
        │  "App wants to access:"                             │
        │  ✓ openid                                           │
        │  ✓ profile                                          │
        │  ✓ email                                            │
        │  ✓ offline_access                                   │
        │                                                      │
        │  User sees: [Allow] [Deny]                          │
        └─────────────────────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
              ALLOW                   DENY
                │                       │
                ▼                       ▼
        ┌──────────────────┐    ┌──────────────────┐
        │ GENERATE AUTH    │    │ REDIRECT TO      │
        │ CODE             │    │ CALLBACK WITH    │
        │                  │    │ ERROR            │
        │ Store in DB:     │    │                  │
        │ - code           │    │ redirect_uri?    │
        │ - user_id        │    │ error=           │
        │ - client_id      │    │ access_denied&   │
        │ - expires_in=600 │    │ state=STATE      │
        │ - scopes         │    └──────────────────┘
        │ - redirect_uri   │
        └──────────────────┘
                │
                ▼
        ┌─────────────────────────────────────────────────────┐
        │  REDIRECT TO CALLBACK                               │
        │                                                      │
        │  redirect_uri?code=AUTH_CODE&state=STATE            │
        │  (and expires in 10 minutes)                        │
        └─────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌─────────────────────────────────────────────────────┐
        │  WAIT FOR TOKEN REQUEST                             │
        │                                                      │
        │  App backend POSTs to /o/token/                     │
        │  with code and code_verifier                        │
        └─────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌─────────────────────────────────────────────────────┐
        │  VALIDATE TOKEN REQUEST                             │
        │                                                      │
        │  ✓ code exists                                      │
        │  ✓ code not expired                                 │
        │  ✓ code not already used                            │
        │  ✓ redirect_uri matches                             │
        │  ✓ client_id matches                                │
        │  ✓ code_verifier valid (PKCE)                       │
        └─────────────────────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
            ERROR                   VALID
                │                       │
                └─────────┬─────────────┘
                          ▼
        ┌─────────────────────────────────────────────────────┐
        │  MARK CODE AS USED                                  │
        │  (Prevents reuse/replay attacks)                    │
        └─────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌─────────────────────────────────────────────────────┐
        │  GENERATE TOKENS                                    │
        │                                                      │
        │  1. Access Token (Bearer, JWT)                      │
        │     - Expires: 3600 seconds (1 hour)                │
        │     - Scopes: openid profile email                  │
        │                                                      │
        │  2. Refresh Token                                   │
        │     - Expires: 86400 seconds (24 hours)             │
        │     - Can request new access token                  │
        │                                                      │
        │  3. ID Token (JWT with user claims)                 │
        │     - Header: {alg: RS256, kid: KEY_ID}             │
        │     - Payload:                                      │
        │       {                                             │
        │         iss: https://sso.hcs.gov                    │
        │         sub: user_id                                │
        │         aud: client_id                              │
        │         exp: timestamp+3600                         │
        │         iat: timestamp                              │
        │         name: User Name                             │
        │         email: user@hcs.gov                         │
        │         picture: url                                │
        │       }                                             │
        │     - Signed: RSA-2048 private key                  │
        │     - Expires: 3600 seconds (1 hour)                │
        └─────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌─────────────────────────────────────────────────────┐
        │  RETURN TOKENS TO CLIENT                            │
        │                                                      │
        │  HTTP 200 OK                                        │
        │  Content-Type: application/json                     │
        │                                                      │
        │  {                                                  │
        │    "access_token": "...",                           │
        │    "token_type": "Bearer",                          │
        │    "expires_in": 3600,                              │
        │    "refresh_token": "...",                          │
        │    "id_token": "..."                                │
        │  }                                                  │
        └─────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌─────────────────────────────────────────────────────┐
        │  AUTHORIZATION COMPLETE ✓                           │
        │                                                      │
        │  Client now has:                                    │
        │  - Valid access token for API access                │
        │  - Valid ID token with user info                    │
        │  - Valid refresh token for renewal                  │
        └─────────────────────────────────────────────────────┘

```

This completes the OAuth2 provider state machine. Each transition is guarded by validation to ensure security and prevent attacks.
