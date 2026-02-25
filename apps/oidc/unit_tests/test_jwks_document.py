from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

class JWKSDocumentViewTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('oidc:oidc-jwks')

    def test_jwks_document_success(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('keys', response.data)
        self.assertIsInstance(response.data['keys'], list)
        # Check at least one key exists (optional, depends on config)
        # self.assertGreaterEqual(len(response.data['keys']), 1)

    def test_jwks_document_wrong_method(self):
        response = self.client.post(self.url)
        self.assertIn(response.status_code, [status.HTTP_405_METHOD_NOT_ALLOWED, status.HTTP_400_BAD_REQUEST])

    def test_jwks_document_unauthenticated(self):
        # JWKS endpoint should be public, but test unauthenticated access
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
