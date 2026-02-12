# OAuth2 Quick Reference Card

## 📍 Key Endpoints

```
LOGIN:   /accounts/login/             (form + social buttons)
TOKEN:   /o/token/                    (get/refresh JWT)
AUTH:    /o/authorize/                (OAuth2 authorization)
SOCIAL:  /social/login/<provider>/    (Google/Facebook/etc)

PROFILE: /api/users/profile/          (Bearer token required)
INFO:    /api/oidc/userinfo/          (Bearer token required)

DISCOVER: /.well-known/openid-configuration/
KEYS:    /api/oidc/jwks/
```

---

## 🔑 Get Your First Token (Copy-Paste Ready)

### Via curl
```bash
curl -X POST http://localhost:8000/o/token/ \
  -d "grant_type=password&username=testuser&password=TestPassword123!&client_id=postman-client"
```

### Via curl (Pretty Print)
```bash
curl -s -X POST http://localhost:8000/o/token/ \
  -d "grant_type=password&username=testuser&password=TestPassword123!&client_id=postman-client" | jq
```

### Via Python
```python
import requests

response = requests.post(
    'http://localhost:8000/o/token/',
    data={
        'grant_type': 'password',
        'username': 'testuser',
        'password': 'TestPassword123!',
        'client_id': 'postman-client'
    }
)

token = response.json()['access_token']
print(f"Token: {token}")
```

---

## 🔐 Use Token in API Call

### curl
```bash
TOKEN="YOUR_TOKEN_HERE"
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/users/profile/
```

### Python
```python
import requests

token = "YOUR_TOKEN_HERE"
headers = {'Authorization': f'Bearer {token}'}

response = requests.get(
    'http://localhost:8000/api/users/profile/',
    headers=headers
)

print(response.json())
```

### JavaScript/Fetch
```javascript
const token = "YOUR_TOKEN_HERE";

fetch('http://localhost:8000/api/users/profile/', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
})
.then(r => r.json())
.then(data => console.log(data))
```

---

## 🔄 Refresh Token

```bash
curl -X POST http://localhost:8000/o/token/ \
  -d "grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN&client_id=postman-client"
```

---

## 📝 Response Format

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",     // Use this
  "token_type": "Bearer",                         // Always "Bearer"
  "expires_in": 3600,                             // Seconds until expiry
  "refresh_token": "abc123xyz789...",             // Use to refresh
  "id_token": "eyJhbGciOiJSUzI1NiJ9..."           // OIDC user claims
}
```

---

## 🧪 Test with Postman

### Import Collection
```
File → Import → HCS_SSO_OAuth2_Postman_Collection.json
```

### Quick Test
1. **Modify**: "Get Token with Username/Password" request
2. **Replace**: `YOUR_CLIENT_ID` → `postman-client`
3. **Send**: Click Send button
4. **Copy**: `access_token` from response
5. **Use**: In "Get User Profile" request
6. **Paste**: As `YOUR_ACCESS_TOKEN`
7. **Send**: Again!

---

## ⚙️ Create OAuth2 App (One-Time)

### Via Admin UI
```
1. Visit: http://localhost:8000/admin/oauth2_provider/application/add/
2. Name: Postman Test
3. Client ID: postman-client
4. Client Type: Public
5. Grant Type: Resource owner password-based
6. Skip Authorization: ✓
7. Redirect URI: http://localhost:8888/callback
8. Save
```

### Via Django Shell
```bash
python manage.py shell
```

```python
from oauth2_provider.models import Application
from django.contrib.auth.models import User

user = User.objects.first()

Application.objects.create(
    name='Postman Test',
    client_id='postman-client',
    user=user,
    client_type='public',
    authorization_grant_type='password',
    redirect_uris='http://localhost:8888/callback'
)
```

---

## 👤 Create Test User (One-Time)

```bash
python manage.py shell
```

```python
from django.contrib.auth.models import User

User.objects.create_user(
    'testuser',
    'test@example.com',
    'TestPassword123!'
)
```

---

## 🐛 Common Issues

### Invalid Client ID
```
✅ Fix: Check /admin/oauth2_provider/application/
      Verify client ID matches exactly
```

### Invalid Credentials
```
✅ Fix: Verify user exists
      python manage.py shell
      User.objects.filter(username='testuser').exists()
```

### Token Expired
```
✅ Fix: Use refresh token or get new one
      POST /o/token/ with grant_type=refresh_token
```

### 401 Unauthorized
```
✅ Fix: Check Authorization header format
      Must be: "Bearer TOKEN_VALUE" (with space)
      Not: "Token TOKEN_VALUE"
```

---

## 📋 Header Format

### Correct ✅
```
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
              ^^^^^^ space ^^^^^^^^^^^^^^^^^^^^
```

### Wrong ❌
```
Authorization: Token abc123xyz          (❌ Old format)
Authorization:Bearer abc123xyz          (❌ No space)
Authorization:Bearer+abc123xyz          (❌ Plus sign)
Authorization: "Bearer abc123xyz"       (❌ Quotes)
```

---

## 🔐 Token Contents (JWT)

Decode at [jwt.io](https://jwt.io) or:

```bash
python -c "import jwt; print(jwt.decode('TOKEN_HERE', options={'verify_signature': False}))"
```

### Sample Payload
```json
{
  "sub": "testuser",                    // User identifier
  "client_id": "postman-client",       // Which app
  "scope": "openid profile email",     // Permissions
  "exp": 1699564800,                   // Expiry timestamp
  "iat": 1699561200,                   // Issued timestamp
  "auth_time": 1699561200              // Login timestamp
}
```

---

## 📚 Documentation Links

| Document | Purpose |
|----------|---------|
| [AUTHENTICATION_README.md](AUTHENTICATION_README.md) | **START HERE** - Overview |
| [POSTMAN_COMPLETE_GUIDE.md](POSTMAN_COMPLETE_GUIDE.md) | Detailed Postman setup |
| [UNIFIED_OAUTH2_SYSTEM.md](UNIFIED_OAUTH2_SYSTEM.md) | Complete reference |
| [IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md) | What changed & why |

---

## 🚀 Next Action

```bash
# 1. Start server
python manage.py runserver

# 2. Get token
curl -X POST http://localhost:8000/o/token/ \
  -d "grant_type=password&username=testuser&password=TestPassword123!&client_id=postman-client"

# 3. Copy token from response

# 4. Use in API call
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8000/api/users/profile/
```

---

## ⚡ Social Providers

```
Google:    /social/login/google-oauth2/
Facebook:  /social/login/facebook/
Microsoft: /social/login/microsoft/
GitHub:    /social/login/github/
LinkedIn:  /social/login/linkedin-oauth2/
```

---

## 📊 Token Expiry

| Token | Expiry |
|-------|--------|
| Access Token | 3600 seconds (1 hour) |
| Refresh Token | 7 days (604800 seconds) |
| Auth Code | 10 minutes (600 seconds) |

---

## ✨ Grant Types

```
password:            Username/password (testing/API)
authorization_code:  Web app OAuth2 flow
refresh_token:       Get new access token
```

---

**Quick Help**: Read [POSTMAN_COMPLETE_GUIDE.md](POSTMAN_COMPLETE_GUIDE.md) for step-by-step setup

**Need More**: Check [UNIFIED_OAUTH2_SYSTEM.md](UNIFIED_OAUTH2_SYSTEM.md#troubleshooting)

