# HCS SSO with OIDC

This repository implements a Single Sign-On (SSO) server with OpenID Connect (OIDC) support and social identity provider integrations.

Features
- OIDC Provider (discovery, JWKS, userinfo, token introspection, revocation)
- OAuth2 support (via django-oauth-toolkit)
- Social authentication (Google, Facebook, GitHub, Microsoft, LinkedIn, generic OIDC)
- Dynamic client registration endpoint (server-side validation recommended)
- Audit logging for social logins and token events

Quickstart (development)

Prerequisites
- Python 3.10+ (project venv provided)
- PostgreSQL (or adjust DATABASES in settings.py)

Setup

1. Create and activate a virtualenv:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Set environment variables (example):

Create .env file in root of the project folder(Here HCS_SSO_WITH_OIDC) with following values

# .env file
DEBUG=True
# Generate a secure secret key for production using: python -c "import secrets; print(secrets.token_urlsafe())"
# python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

SECRET_KEY="miv2t_l&gzy)omi)gqkc=88mwdvny^&77zj!6^fz51uuw#wsm%"

# DATABASE_URL=sqlite:///db.sqlite3

POSTGRES_DB=hcs_sso_oidc_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=Darkhorse@7428
POSTGRES_HOST=72.60.218.27
POSTGRES_PORT=5432

OIDC_CLIENT_ID=your-oidc-client-id
OIDC_CLIENT_SECRET=your-oidc-client-secret
OIDC_URL = 'https://sso.diseso.com'  # Example



# OAuth Toolkit
OAUTH2_PROVIDER_APPLICATION_MODEL=oauth2_provider.Application
OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL=oauth2_provider.AccessToken

# Allauth
SITE_ID=1
ACCOUNT_EMAIL_VERIFICATION=optional
ACCOUNT_AUTHENTICATION_METHOD=email

# Social Providers (Add your credentials)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
FACEBOOK_CLIENT_ID=your-facebook-app-id
FACEBOOK_CLIENT_SECRET=your-facebook-app-secret
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret

SECURE_SSL_REDIRECT=False
SESSION_COOKIE_SECURE=False
CSRF_COOKIE_SECURE=False




```bash
export DEBUG=True
export SECRET_KEY="$(python -c 'from django.core.management.utils import get_random_secret_key; print(_ )')"
export POSTGRES_DB=hcs_sso_oidc_db
export POSTGRES_USER=postgres
export POSTGRES_PASSWORD=postgres
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
```

3. Run migrations and start the dev server:

```bash
python manage.py migrate
python manage.py runserver
```

Testing

Run the provided social pipeline tests scaffold:

```bash
python manage.py test apps.social.test_pipeline -v 2
```

Important files
- `sso/settings.py` — project configuration and security settings
- `sso/urls.py` — URL routing for OIDC, OAuth2, social and API
- `apps/oidc/` — OIDC provider implementation (views, validators, jwks)
- `apps/social/` — social auth backends and pipeline
- `apps/users/` — user management endpoints

Security notes (production)
- Set `DEBUG=False` and provide a strong `SECRET_KEY`.
- Ensure `ALLOWED_HOSTS` is configured for your domain.
- Use managed secrets for OIDC private key (do not auto-generate in production).
- Configure TLS (HTTPS) and ensure `SECURE_*` settings are enabled (they are enforced when `DEBUG=False`).
- Protect token introspection and revocation endpoints: clients must authenticate (HTTP Basic or POST credentials).
- Disable dev tools (`debug_toolbar`, `silk`) in production.

OIDC discovery
- The discovery document is served at `/.well-known/openid-configuration/` and contains issuer, jwks_uri and endpoints used by clients.
- JWKS is served via the JWKS endpoint and used to validate ID token signatures.

Social providers
- Configure provider client IDs and secrets in environment variables (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, etc.) in `sso/settings.py`.

Next steps / Recommendations
- Move OIDC key management to a secrets manager (HashiCorp Vault, AWS KMS).
- Replace the simplified password-reset flow with Django's secure password-reset email workflow.
- Add integration tests covering OIDC flows (authorization code, token issuance, userinfo).

License
- This project contains example code and is intended as a starting point. Add an appropriate license file.
