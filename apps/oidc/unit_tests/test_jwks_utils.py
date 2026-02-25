from django.test import TestCase
from unittest.mock import patch, MagicMock
from apps.oidc.utils import jwks
import base64
from pathlib import Path

class JWKSUtilsTests(TestCase):
    @patch('apps.oidc.utils.jwks.settings')
    @patch('apps.oidc.utils.jwks.serialization')
    def test_generate_jwks_document(self, mock_serialization, mock_settings):
        mock_settings.OIDC_PUBLIC_KEY_PATH = '/fake/path/public.pem'
        mock_settings.BASE_DIR = Path('/fake/base')
        fake_public_key = MagicMock()
        fake_numbers = MagicMock()
        fake_numbers.n = 123456789
        fake_numbers.e = 65537
        fake_public_key.public_numbers.return_value = fake_numbers
        mock_serialization.load_pem_public_key.return_value = fake_public_key
        with patch('builtins.open', new_callable=MagicMock) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = b'fakepem'
            result = jwks.generate_jwks_document()
        self.assertIn('keys', result)
        self.assertEqual(result['keys'][0]['kty'], 'RSA')
        self.assertEqual(result['keys'][0]['alg'], 'RS256')
        self.assertEqual(result['keys'][0]['use'], 'sig')
        self.assertEqual(result['keys'][0]['kid'], '1')
        self.assertEqual(result['keys'][0]['n'], jwks.int_to_base64(123456789))
        self.assertEqual(result['keys'][0]['e'], jwks.int_to_base64(65537))

    def test_int_to_base64(self):
        n = 123456789
        b64 = jwks.int_to_base64(n)
        self.assertIsInstance(b64, str)
        # Should decode back to original integer
        decoded = int.from_bytes(base64.urlsafe_b64decode(b64 + '=='), 'big')
        self.assertEqual(decoded, n)

    @patch('apps.oidc.utils.jwks.cache')
    @patch('apps.oidc.utils.jwks.generate_jwks_document')
    def test_get_jwks_from_cache_or_generate(self, mock_generate_jwks_document, mock_cache):
        # Test cache hit
        mock_cache.get.return_value = {'keys': ['cached']}
        result = jwks.get_jwks_from_cache_or_generate()
        self.assertEqual(result, {'keys': ['cached']})
        # Test cache miss
        mock_cache.get.return_value = None
        mock_generate_jwks_document.return_value = {'keys': ['generated']}
        result = jwks.get_jwks_from_cache_or_generate()
        self.assertEqual(result, {'keys': ['generated']})
        mock_cache.set.assert_called()
