# Postman OAuth2 Testing - Complete Walkthrough

## Table of Contents
1. [One-Time Setup](#one-time-setup) (5 minutes)
2. [Get Your First Token](#get-your-first-token) (2 minutes)
3. [Use Token in API Calls](#use-token-in-api-calls) (1 minute)
4. [Common Issues & Fixes](#common-issues--fixes)
5. [Advanced Flows](#advanced-flows)

---

## One-Time Setup

### 1A. Start Your Django Server
```bash
cd /Users/dhrubajyotiborah/Documents/Projects/hcs_sso_with_oidc
python manage.py runserver
```

Visit: http://localhost:8000/admin/ (should see Django admin)

### 1B. Create Test User
```bash
python manage.py shell
```

In the Python shell:
```python
from django.contrib.auth.models import User
User.objects.create_user(
    username='testuser',
    email='test@example.com',
    password='TestPassword123!'
)
print("User created!")
exit()
```

### 1C. Create OAuth2 Application

Visit: http://localhost:8000/admin/oauth2_provider/application/add/

**Fill in these fields:**
| Field | Value |
|-------|-------|
| Name | `Postman Test Client` |
| Client ID | `postman-client` |
| Client Secret | `(leave blank - will auto-generate or use default)` |
| Client Type | `Public` |
| Authorization Grant Type | `Resource owner password-based` |
| Skip Authorization | `✓ Check this` |
| Redirect URIs | `http://localhost:8888/callback` |

**Click Save**

✅ Setup complete! You now have:
- Test user: `testuser` / `TestPassword123!`
- OAuth2 app: `postman-client`

---

## Get Your First Token

### Method 1: Using Postman GUI (Recommended)

#### Step 1: Open Postman and Create New Request

**Request Name**: `Get OAuth2 Token - Password Grant`

#### Step 2: Configure Request

Set these values:

| Setting | Value |
|---------|-------|
| Method | `POST` |
| URL | `http://localhost:8000/o/token/` |

#### Step 3: Add Headers

Click **Headers** tab, add:

| Key | Value |
|-----|-------|
| `Content-Type` | `application/x-www-form-urlencoded` |

#### Step 4: Add Body

Click **Body** tab, select **form-data**, add:

| Key | Value |
|-----|-------|
| `grant_type` | `password` |
| `username` | `testuser` |
| `password` | `TestPassword123!` |
| `client_id` | `postman-client` |

#### Step 5: Send Request

Click **Send**

#### Step 6: See Response

You'll get:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsICJjbGllbnRfaWQiOiAicG9zdG1hbi1jbGllbnQiLCAiZXhwIjogMTY5OTU2NDgwMH0...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "abc123xyz789...",
  "id_token": "eyJhbGciOiJSUzI1NiJ9..."
}
```

**📌 IMPORTANT**: Copy the `access_token` value (without quotes) for next step

---

### Method 2: Using curl (Command Line)

```bash
curl -X POST http://localhost:8000/o/token/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=testuser&password=TestPassword123!&client_id=postman-client"
```

---

## Use Token in API Calls

### Get User Profile

#### In Postman GUI:

1. **Create New Request**
   - Method: `GET`
   - URL: `http://localhost:8000/api/users/profile/`

2. **Add Authorization Header**
   
   Click **Headers** tab, add:
   ```
   Authorization: Bearer YOUR_ACCESS_TOKEN_HERE
   ```
   
   Replace `YOUR_ACCESS_TOKEN_HERE` with the token from previous step

3. **Send**
   
   You'll see your user profile:
   ```json
   {
     "id": 1,
     "username": "testuser",
     "email": "test@example.com",
     "first_name": "",
     "last_name": "",
     "is_staff": false,
     "date_joined": "2024-01-15T10:30:00Z"
   }
   ```

#### Using curl:

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE" \
  http://localhost:8000/api/users/profile/
```

---

## Common Issues & Fixes

### ❌ "Error: invalid_client"

**Cause**: Client ID wrong or app doesn't exist

**Fix**:
1. Go to http://localhost:8000/admin/oauth2_provider/application/
2. Confirm app exists with name `Postman Test Client`
3. Copy the exact `Client ID` value
4. Use that in your request

---

### ❌ "Error: invalid_grant"

**Cause**: Username or password wrong

**Fix**:
1. Check you created the user:
   ```bash
   python manage.py shell
   >>> from django.contrib.auth.models import User
   >>> User.objects.filter(username='testuser').exists()
   # Should return: True
   ```
2. Try logging in at http://localhost:8000/accounts/login/
3. If login page login fails, user/password is wrong

---

### ❌ "Error: redirect_uri_mismatch"

**Cause**: Callback URL doesn't match registered URL

**Fix**:
1. In admin app, confirm Redirect URIs includes: `http://localhost:8888/callback`
2. Match exactly (case-sensitive, including http/https)
3. For testing, use: `http://localhost:8888/callback`

---

### ❌ "401 Unauthorized" when using token

**Cause**: Token expired or not in Authorization header

**Fix**:
1. Get a fresh token (they expire in 3600 seconds)
2. Ensure header is exactly: `Authorization: Bearer TOKEN_VALUE`
3. No extra spaces or quotes

---

### ❌ "PKCE Required" Error

**Cause**: Using authorization code flow without PKCE

**Fix**: For testing with password grant (simplest), this won't happen

---

## Advanced Flows

### Refresh Token (Get New Access Token)

When your access token expires (after 3600 seconds):

**Postman:**
1. Method: `POST`
2. URL: `http://localhost:8000/o/token/`
3. Body (form-data):
   ```
   grant_type: refresh_token
   refresh_token: YOUR_REFRESH_TOKEN_HERE
   client_id: postman-client
   ```
4. Send

**Response**: New `access_token` with same format

**curl**:
```bash
curl -X POST http://localhost:8000/o/token/ \
  -d "grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN&client_id=postman-client"
```

---

### Authorization Code Flow (For Web Apps)

Use this when you're building a web app that needs user consent.

#### Step 1: Get Authorization Code

Visit in browser:
```
http://localhost:8000/o/authorize/?client_id=postman-client&redirect_uri=http://localhost:8888/callback&response_type=code&scope=openid profile email&state=random123&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256
```

(For simplicity in testing, use password grant instead)

---

### OIDC UserInfo Endpoint

Get current user's OIDC profile:

**Postman:**
1. Method: `GET`
2. URL: `http://localhost:8000/api/oidc/userinfo/`
3. Header:
   ```
   Authorization: Bearer YOUR_ACCESS_TOKEN
   ```
4. Send

**Response**:
```json
{
  "sub": "testuser",
  "email": "test@example.com",
  "email_verified": true,
  "name": "Test User",
  "given_name": "Test",
  "family_name": "User",
  "locale": "en-US"
}
```

---

## Testing Checklist

- [ ] Django server running (`python manage.py runserver`)
- [ ] Test user created (`testuser`)
- [ ] OAuth2 app created (`postman-client`)
- [ ] Got access token via password grant
- [ ] Called API with token in Authorization header
- [ ] Got 200 response with user data
- [ ] Tested with curl (optional)

---

## Quick Reference: All Endpoints

| Purpose | Method | URL | Auth Header |
|---------|--------|-----|-------------|
| Get Token | POST | `/o/token/` | None |
| Refresh Token | POST | `/o/token/` | None |
| Get Profile | GET | `/api/users/profile/` | `Bearer TOKEN` |
| Get OIDC Info | GET | `/api/oidc/userinfo/` | `Bearer TOKEN` |
| OIDC Discovery | GET | `/.well-known/openid-configuration/` | None |
| JWKS | GET | `/api/oidc/jwks/` | None |
| Admin | GET | `/admin/` | Django session |

---

## Next Steps

- ✅ Test password grant flow (done!)
- [ ] Test social login (Google/Facebook)
- [ ] Test authorization code flow with PKCE
- [ ] Integrate into your frontend
- [ ] Test on mobile app (iOS/Android)

---

## Need Help?

1. **Token isn't working?** → Check it hasn't expired (3600 seconds)
2. **App won't create?** → Check Django admin is accessible at `/admin/`
3. **Can't find endpoints?** → Check Django debug toolbar: `?__debug__=1`
4. **Still stuck?** → Check logs:
   ```bash
   tail -f logs/django.log
   ```

