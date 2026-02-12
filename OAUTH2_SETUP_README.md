# OAuth 2.0 / OpenID Connect SSO Configuration - Quick Start

## What Was Changed

Your SSO project is now configured to handle OAuth 2.0 authorization requests with a multi-step authentication flow that lets users choose between organization credentials or social login.

### Files Modified

1. **`sso/settings.py`** - Added login URL configuration
   ```python
   LOGIN_URL = '/login/'
   LOGIN_REDIRECT_URL = '/'
   LOGOUT_REDIRECT_URL = '/'
   ```

2. **`sso/urls.py`** - Added organization login view routing
   ```python
   path('login/', TemplateView.as_view(template_name='login.html'), name='login'),
   path('accounts/login/', OrganizationLoginView.as_view(), name='organization_login'),
   ```

3. **`apps/core/views.py`** - Created `OrganizationLoginView`
   - Handles username/password authentication
   - Preserves OAuth2 `next` parameter for seamless redirect
   - Logs user in and returns to authorization flow

4. **`templates/registration/login.html`** - Created modern organization login form
   - Clean, responsive design with Bootstrap 5
   - Username/password fields
   - Error handling and security notices
   - Link to return to authentication method selection

---

## How It Works

### Complete Flow:

```
External App → http://localhost:8000/o/authorize/?...
                         ↓
                  User authenticated?
                    ↙        ↘
                  NO          YES
                  ↓            ↓
            /login/       Authorization
                ↓          Consent Page
           Choose Method        ↓
              ↙      ↘     Grant/Deny
            Org    Social    ↓
            ↓        ↓     Authorization
      /accounts/   Provider  Code
       login/      Login      ↓
           ↓                redirect_uri
        Validate           + code
        Credentials         + state
           ↓
        Create Session
           ↓
        Redirect to
        OAuth2 with
        'next' parameter
```

---

## Testing the Flow

### Step 1: Create a Test User

```bash
python manage.py createsuperuser
# OR
python manage.py shell
>>> from django.contrib.auth.models import User
>>> User.objects.create_user(username='testuser', password='TestPass123!')
```

### Step 2: Register an OAuth2 Application

```
1. Start server: python manage.py runserver
2. Visit: http://localhost:8000/o/applications/
3. Click "New Application"
4. Fill form:
   - Client type: Public (for SPAs)
   - Authorization grant type: Authorization code
   - Redirect URIs: http://localhost:3000/callback (or your app's callback)
5. Save and note the Client ID
```

### Step 3: Test Authorization Flow

Visit in your browser:
```
http://localhost:8000/o/authorize/?
  client_id=YOUR_CLIENT_ID&
  redirect_uri=http://localhost:3000/callback&
  response_type=code&
  scope=openid+profile+email&
  state=random_state_value&
  code_challenge=your_pkce_challenge
```

### Expected Behavior:

1. ✅ Not logged in? → Redirects to `/login/`
2. ✅ Click "HCS Account" → Goes to `/accounts/login/`
3. ✅ Enter credentials → Validates username/password
4. ✅ Success → Redirects back to OAuth2 authorization
5. ✅ Shows scope consent → "Allow this app to access your profile?"
6. ✅ Click "Authorize" → Generates auth code
7. ✅ Redirected to callback with `code=...&state=...`

---

## Key URLs

| URL | Purpose | Method |
|-----|---------|--------|
| `/` | Home page | GET |
| `/login/` | Choose auth method (Org or Social) | GET |
| `/accounts/login/` | Organization credentials form | GET, POST |
| `/o/authorize/` | OAuth2 authorization endpoint | GET |
| `/o/token/` | Exchange code for tokens | POST |
| `/.well-known/openid-configuration/` | OIDC discovery | GET |
| `/api/oidc/jwks/` | JWT signing keys | GET |
| `/social/login/<provider>/` | Social login (google, facebook, etc) | GET |

---

## Environment Variables Needed

Create a `.env` file with these for social login:

```env
# Google
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Facebook
FACEBOOK_CLIENT_ID=your_facebook_app_id
FACEBOOK_CLIENT_SECRET=your_facebook_app_secret

# Microsoft
MICROSOFT_CLIENT_ID=your_microsoft_client_id
MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret

# GitHub
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# LinkedIn
LINKEDIN_CLIENT_ID=your_linkedin_client_id
LINKEDIN_CLIENT_SECRET=your_linkedin_client_secret
```

---

## Important Notes

### ✅ PKCE is Required
- Protects authorization code from interception
- Required for public clients (SPAs, mobile apps)
- Must include `code_challenge` in authorization request
- Must include `code_verifier` in token request

### ✅ State Parameter is Required
- Prevents CSRF attacks
- Must be random and unpredictable
- Client must validate state in callback

### ✅ Redirect URI Must Match
- Must be registered during OAuth2 app creation
- Must match exactly (case-sensitive, including scheme)
- Cannot use wildcards

### ✅ User Must Exist in Database
- Organization login only works for Django users
- Create users via Django admin or management commands
- Email/username must match exactly

---

## Customization Options

### Change Login Text

Edit `/sso/templates/login.html`:
- Lines 65-70: "HCS Account" button text and description
- Line 72: "Choose Your Login Method" heading

### Add More Social Providers

In `settings.py`, add to `AUTHENTICATION_BACKENDS`:
```python
'social_core.backends.twitter.TwitterOAuth2',  # Example
```

Then configure credentials in `.env`.

### Custom Redirect After Login

In `OrganizationLoginView` (apps/core/views.py), modify `form_valid()` method to customize redirect logic.

### Styling

Bootstrap classes are used. Edit CSS in:
- `/sso/templates/login.html` (lines 20-50)
- `/sso/templates/index.html`

---

## Troubleshooting

### "No such table: auth_user"
```bash
python manage.py migrate
```

### "Client matching query does not exist"
- Register an OAuth2 application at `/o/applications/`
- Use the correct Client ID in your test URL

### User not redirected after organization login
- Check `LOGIN_REDIRECT_URL` in settings
- Verify `next` parameter is being passed correctly
- Check browser console for JavaScript errors

### Social login not working
- Verify provider credentials in `.env`
- Check redirect URI is whitelisted in provider dashboard
- Ensure `social_django` is in `INSTALLED_APPS`

---

## Security Checklist

- [ ] `DEBUG = False` in production
- [ ] Set strong `SECRET_KEY`
- [ ] Enable HTTPS (`SECURE_SSL_REDIRECT = True`)
- [ ] Configure CORS for your frontend domain
- [ ] Use environment variables for all secrets
- [ ] Enable HSTS headers
- [ ] Test CSRF protection
- [ ] Verify PKCE is enforced
- [ ] Monitor failed login attempts
- [ ] Regular security audits

---

## Next Steps

1. **Test the complete flow** - Follow testing steps above
2. **Configure social providers** - Add provider credentials
3. **Customize templates** - Match your organization branding
4. **Set up monitoring** - Log authentication events
5. **Plan deployment** - Consider infrastructure needs

---

## Full Documentation

See `SSO_OAUTH2_FLOW_GUIDE.md` for detailed technical documentation.
