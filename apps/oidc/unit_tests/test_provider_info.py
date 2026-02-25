from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

class OIDCProviderInfoViewTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('oidc:oidc-provider-info')

    def test_provider_info_success(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check for required OIDC metadata fields
        self.assertIn('issuer', response.data)
        self.assertIn('authorization_endpoint', response.data)
        self.assertIn('token_endpoint', response.data)
        self.assertIn('jwks_uri', response.data)
        self.assertIn('userinfo_endpoint', response.data)

    def test_provider_info_wrong_method(self):
        response = self.client.post(self.url)
        self.assertIn(response.status_code, [status.HTTP_405_METHOD_NOT_ALLOWED, status.HTTP_400_BAD_REQUEST])

    def test_provider_info_unauthenticated(self):
        # OIDC provider info should be public, but test unauthenticated access
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
