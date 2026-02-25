from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from oauth2_provider.models import Application

User = get_user_model()

class ClientRegistrationViewTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='testpass123'
        )
        self.group, _ = Group.objects.get_or_create(name='API_READERS')
        self.user.groups.add(self.group)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_register_valid_client(self):
        url = reverse('oidc:oidc-register')
        data = {
            'client_name': 'Test Client',
            'redirect_uris': ['http://localhost/callback'],
            'grant_types': ['password'],
            'response_types': ['token'],
            'application_type': 'web',
            'token_endpoint_auth_method': 'client_secret_basic',
            'scope': 'openid profile email',
        }
        response = self.client.post(url, data)
        self.assertIn(response.status_code, [status.HTTP_201_CREATED, status.HTTP_200_OK])
        self.assertIn('client_id', response.data)
        self.assertIn('client_secret', response.data)

    def test_register_missing_fields(self):
        url = reverse('oidc:oidc-register')
        data = {
            'client_name': 'Test Client',
            # Missing client_type, authorization_grant_type, redirect_uris
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_unauthenticated(self):
        self.client.force_authenticate(user=None)
        url = reverse('oidc:oidc-register')
        data = {
            'client_name': 'Test Client',
            'client_type': 'confidential',
            'authorization_grant_type': 'password',
            'redirect_uris': 'http://localhost/callback',
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_register_wrong_method(self):
        url = reverse('oidc:oidc-register')
        response = self.client.get(url)
        self.assertIn(response.status_code, [status.HTTP_405_METHOD_NOT_ALLOWED, status.HTTP_400_BAD_REQUEST])
