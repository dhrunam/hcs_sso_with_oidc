#!/bin/bash
# OAuth2 / OpenID Connect Flow Testing Script
# This script demonstrates testing the complete OAuth2 authorization flow

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     OAuth2/OpenID Connect SSO Flow Testing Guide          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Configuration
SSO_HOST="${1:-http://localhost:8000}"
CLIENT_ID="${2:-YOUR_CLIENT_ID}"
REDIRECT_URI="${3:-http://localhost:3000/callback}"

echo -e "${YELLOW}Configuration:${NC}"
echo "SSO Host: $SSO_HOST"
echo "Client ID: $CLIENT_ID"
echo "Redirect URI: $REDIRECT_URI"
echo ""

# =====================================================
# STEP 1: Create Test User
# =====================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 1: Create Organization Test User${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Run this command in your Django shell:${NC}"
echo ""
echo "python manage.py shell"
echo ""
echo "Then execute:"
echo ""
cat << 'EOF'
from django.contrib.auth.models import User
# Create a test user for organization login
user = User.objects.create_user(
    username='testuser',
    email='testuser@hcs.gov',
    password='TestPassword123!'
)
print(f"✓ User created: {user.username} ({user.email})")
EOF
echo ""
echo ""

# =====================================================
# STEP 2: Register OAuth2 Application
# =====================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 2: Register OAuth2 Application${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Option A: Use Django Admin UI${NC}"
echo "1. Start server: python manage.py runserver"
echo "2. Visit: http://localhost:8000/admin/oauth2_provider/application/"
echo "3. Click 'Add Application'"
echo "4. Fill form:"
echo "   - Client type: Public"
echo "   - Authorization grant type: Authorization code"
echo "   - Redirect URIs: http://localhost:3000/callback"
echo "5. Save and note the Client ID"
echo ""

echo -e "${YELLOW}Option B: Use Django Shell${NC}"
echo ""
echo "python manage.py shell"
echo ""
cat << 'EOF'
from oauth2_provider.models import Application
from django.contrib.auth.models import User

# Get or create test user
user = User.objects.get(username='testuser')

# Create OAuth2 application
app = Application.objects.create(
    name='Test Client App',
    client_type=Application.CLIENT_PUBLIC,
    authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
    user=user,
    redirect_uris='http://localhost:3000/callback'
)
print(f"✓ Application created")
print(f"  Client ID: {app.client_id}")
print(f"  Client Secret: {app.client_secret}")
EOF
echo ""
echo ""

# =====================================================
# STEP 3: Generate PKCE Challenge
# =====================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 3: Generate PKCE Challenge${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Run this command in Python:${NC}"
echo ""
echo "python"
echo ""
cat << 'EOF'
import secrets
import hashlib
import base64

# Generate code verifier (43-128 characters)
code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

# Generate code challenge
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode('utf-8')).digest()
).decode('utf-8').rstrip('=')

print(f"Code Verifier: {code_verifier}")
print(f"Code Challenge: {code_challenge}")
EOF
echo ""
echo ""

# =====================================================
# STEP 4: Build Authorization URL
# =====================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 4: Build Authorization URL${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Template:${NC}"
echo ""
cat << 'EOF'
http://localhost:8000/o/authorize/?
  client_id=YOUR_CLIENT_ID&
  redirect_uri=http://localhost:3000/callback&
  response_type=code&
  scope=openid+profile+email&
  state=random_state_value&
  code_challenge=YOUR_CODE_CHALLENGE&
  code_challenge_method=S256
EOF
echo ""
echo -e "${YELLOW}Example (copy and paste):${NC}"
echo ""
echo "http://localhost:8000/o/authorize/?client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid+profile+email&state=random123&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256"
echo ""
echo ""

# =====================================================
# STEP 5: Manual Flow Test
# =====================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 5: Manual Flow Test in Browser${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Follow these steps:${NC}"
echo ""
echo "1. Open the authorization URL from STEP 4 in your browser"
echo "   → Not authenticated? Redirects to /login/"
echo ""
echo "2. At /login/, click 'HCS Account' button"
echo "   → Directed to /accounts/login/"
echo ""
echo "3. Enter credentials:"
echo "   Username: testuser"
echo "   Password: TestPassword123!"
echo "   → Login form validates credentials"
echo ""
echo "4. On success, redirected back to OAuth2 authorization page"
echo "   → Shows scope consent: 'Allow app to access your profile?'"
echo ""
echo "5. Click 'Authorize'"
echo "   → Authorization code is generated"
echo ""
echo "6. Redirected to callback URL with code:"
echo "   http://localhost:3000/callback?code=YOUR_AUTH_CODE&state=random123"
echo ""
echo ""

# =====================================================
# STEP 6: Exchange Code for Tokens
# =====================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 6: Exchange Authorization Code for Tokens${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Using curl:${NC}"
echo ""
echo "curl -X POST http://localhost:8000/o/token/ \\"
echo "  -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "  -d 'grant_type=authorization_code' \\"
echo "  -d 'code=YOUR_AUTH_CODE' \\"
echo "  -d 'client_id=YOUR_CLIENT_ID' \\"
echo "  -d 'redirect_uri=http://localhost:3000/callback' \\"
echo "  -d 'code_verifier=YOUR_CODE_VERIFIER'"
echo ""
echo -e "${YELLOW}Expected response:${NC}"
echo ""
cat << 'EOF'
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "id_token": "eyJ..."
}
EOF
echo ""
echo ""

# =====================================================
# STEP 7: Decode ID Token
# =====================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 7: Decode JWT ID Token${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Using Python:${NC}"
echo ""
echo "python"
echo ""
cat << 'EOF'
import base64
import json

id_token = "YOUR_ID_TOKEN_HERE"  # From token response

# Split JWT parts
header, payload, signature = id_token.split('.')

# Decode payload (add padding if needed)
payload += '=' * (4 - len(payload) % 4)
decoded = base64.urlsafe_b64decode(payload)
claims = json.loads(decoded)

print(json.dumps(claims, indent=2))
# Expected claims: sub, iss, aud, exp, iat, name, email, picture, etc.
EOF
echo ""
echo ""

# =====================================================
# STEP 8: Verify ID Token Signature
# =====================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 8: Verify ID Token Signature (Get JWKS)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Get public keys from JWKS endpoint:${NC}"
echo ""
echo "curl http://localhost:8000/api/oidc/jwks/"
echo ""
echo -e "${YELLOW}Response:${NC}"
echo ""
cat << 'EOF'
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "...",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
EOF
echo ""
echo ""

# =====================================================
# STEP 9: Get User Info
# =====================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 9: Get User Information${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Using access token:${NC}"
echo ""
echo "curl -H 'Authorization: Bearer YOUR_ACCESS_TOKEN' \\"
echo "  http://localhost:8000/api/oidc/userinfo/"
echo ""
echo -e "${YELLOW}Expected response:${NC}"
echo ""
cat << 'EOF'
{
  "sub": "1",
  "name": "Test User",
  "email": "testuser@hcs.gov",
  "email_verified": true,
  "picture": "...",
  "given_name": "Test",
  "family_name": "User"
}
EOF
echo ""
echo ""

# =====================================================
# STEP 10: Test Social Login
# =====================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 10: Test Social Login (Alternative)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}At /login/ page, instead of clicking 'HCS Account':${NC}"
echo ""
echo "1. Click 'Continue with Google' (or other provider)"
echo "   → Redirects to Google login page"
echo ""
echo "2. Authenticate with your Google account"
echo "   → Google redirects back with user info"
echo ""
echo "3. django-social-auth creates/updates user"
echo "   → User is logged in"
echo ""
echo "4. Redirected back to OAuth2 authorization"
echo "   → Shows scope consent (same as org login)"
echo ""
echo "5. Click 'Authorize'"
echo "   → Authorization code generated"
echo ""
echo ""

# =====================================================
# Common Test Cases
# =====================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}COMMON TEST CASES${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Test Case 1: Happy Path${NC}"
echo "Expected: Unauthenticated → /login → Org login → Authorization → Token"
echo ""
echo -e "${YELLOW}Test Case 2: Social Login${NC}"
echo "Expected: Choose social provider → Provider auth → Authorization → Token"
echo ""
echo -e "${YELLOW}Test Case 3: Invalid Credentials${NC}"
echo "Expected: Wrong password → Error message → Return to login form"
echo ""
echo -e "${YELLOW}Test Case 4: User Denies Permission${NC}"
echo "Expected: Show scope consent → User clicks 'Deny' → Error redirect"
echo ""
echo -e "${YELLOW}Test Case 5: Invalid PKCE Challenge${NC}"
echo "Expected: Authorization request rejected with error"
echo ""
echo -e "${YELLOW}Test Case 6: Mismatched Redirect URI${NC}"
echo "Expected: Request rejected if URI doesn't match registered"
echo ""
echo ""

# =====================================================
# Useful Endpoints
# =====================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}USEFUL ENDPOINTS${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}OpenID Connect Discovery:${NC}"
echo "GET http://localhost:8000/.well-known/openid-configuration/"
echo ""
echo -e "${GREEN}JWKS (Public Keys):${NC}"
echo "GET http://localhost:8000/api/oidc/jwks/"
echo ""
echo -e "${GREEN}Token Introspection:${NC}"
echo "POST http://localhost:8000/api/oidc/token/introspect/"
echo ""
echo -e "${GREEN}Token Revocation:${NC}"
echo "POST http://localhost:8000/api/oidc/token/revoke/"
echo ""
echo -e "${GREEN}User Info:${NC}"
echo "GET/POST http://localhost:8000/api/oidc/userinfo/"
echo ""
echo -e "${GREEN}Admin Panel:${NC}"
echo "http://localhost:8000/admin/"
echo ""
echo ""

echo -e "${GREEN}✓ Setup complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Create test user (STEP 1)"
echo "2. Register OAuth2 app (STEP 2)"
echo "3. Generate PKCE challenge (STEP 3)"
echo "4. Test authorization flow (STEP 5)"
echo ""
