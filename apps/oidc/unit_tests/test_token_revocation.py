from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework import status
from oauth2_provider.models import Application, AccessToken, RefreshToken
from oauthlib.common import generate_token
from django.utils import timezone

User = get_user_model()

class TokenRevocationViewTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='testpass123'
        )
        self.group, _ = Group.objects.get_or_create(name='API_READERS')
        self.user.groups.add(self.group)
        self.client = APIClient()

        # Create OAuth2 application
        self.application = Application.objects.create(
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            name='TestApp',
            redirect_uris='http://localhost',
        )

        # Create access and refresh tokens
        self.access_token = AccessToken.objects.create(
            user=self.user,
            token=generate_token(),
            application=self.application,
            expires=timezone.now() + timezone.timedelta(hours=1),
            scope='openid profile email',
        )
        self.refresh_token = RefreshToken.objects.create(
            user=self.user,
            token=generate_token(),
            application=self.application,
            access_token=self.access_token,
        )

    def test_revoke_access_token(self):
        url = reverse('oidc:oidc-revoke')
        data = {
            'token': self.access_token.token,
            'token_type_hint': 'access_token',
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(AccessToken.objects.filter(token=self.access_token.token).exists())

    def test_revoke_refresh_token(self):
        url = reverse('oidc:oidc-revoke')
        data = {
            'token': self.refresh_token.token,
            'token_type_hint': 'refresh_token',
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(RefreshToken.objects.filter(token=self.refresh_token.token).exists())

    def test_revoke_invalid_token(self):
        url = reverse('oidc:oidc-revoke')
        data = {
            'token': 'invalidtoken',
            'token_type_hint': 'access_token',
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should not delete any tokens
        self.assertTrue(AccessToken.objects.filter(token=self.access_token.token).exists())
        self.assertTrue(RefreshToken.objects.filter(token=self.refresh_token.token).exists())

    def test_revoke_without_client_credentials(self):
        url = reverse('oidc:oidc-revoke')
        data = {'token': self.access_token.token, 'token_type_hint': 'access_token'}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_revoke_with_wrong_client_credentials(self):
        url = reverse('oidc:oidc-revoke')
        data = {
            'token': self.access_token.token,
            'token_type_hint': 'access_token',
            'client_id': 'wrongid',
            'client_secret': 'wrongsecret',
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_revoke_with_missing_token(self):
        url = reverse('oidc:oidc-revoke')
        data = {
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_revoke_with_empty_token(self):
        url = reverse('oidc:oidc-revoke')
        data = {
            'token': '',
            'token_type_hint': 'access_token',
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_revoke_with_get_method(self):
        url = reverse('oidc:oidc-revoke')
        response = self.client.get(url)
        self.assertIn(response.status_code, [status.HTTP_405_METHOD_NOT_ALLOWED, status.HTTP_400_BAD_REQUEST])
