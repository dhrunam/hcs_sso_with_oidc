# apps/oidc/utils/jwks.py
import base64
from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)

def generate_jwks_document():
    """Generate JSON Web Key Set document"""
    # Get public key path from settings
    public_key_path = getattr(
        settings, 
        'OIDC_PUBLIC_KEY_PATH',
        settings.BASE_DIR / 'oidc_public_key.pem'
    )
    
    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    
    # Extract RSA parameters
    public_numbers = public_key.public_numbers()
    
    # Convert to JWK format
    jwks = {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": "1",
            "n": int_to_base64(public_numbers.n),
            "e": int_to_base64(public_numbers.e),
            "alg": "RS256",
        }]
    }
    
    return jwks


def int_to_base64(number):
    """Convert integer to Base64URL"""
    byte_length = (number.bit_length() + 7) // 8
    bytes_val = number.to_bytes(byte_length, 'big')
    return base64.urlsafe_b64encode(bytes_val).decode('utf-8').rstrip('=')


def get_jwks_from_cache_or_generate():
    """Get JWKS from cache or generate new"""
    cache_key = 'oidc_jwks'
    jwks = cache.get(cache_key)
    
    if jwks is None:
        jwks = generate_jwks_document()
        cache.set(cache_key, jwks, timeout=86400)  # 24 hours
    
    return jwks