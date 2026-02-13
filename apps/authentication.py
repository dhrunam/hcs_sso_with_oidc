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