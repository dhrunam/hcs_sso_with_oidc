from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework import status
from oauth2_provider.models import Application, AccessToken
from oauthlib.common import generate_token
from django.utils import timezone

User = get_user_model()

class SessionManagementViewTests(APITestCase):
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

        # Create access token
        self.access_token = AccessToken.objects.create(
            user=self.user,
            token=generate_token(),
            application=self.application,
            expires=timezone.now() + timezone.timedelta(hours=1),
            scope='openid profile email',
        )

    def test_sessions_authenticated(self):
        url = reverse('oidc:oidc-sessions')
        auth_header = f'Bearer {self.access_token.token}'
        response = self.client.get(url, HTTP_AUTHORIZATION=auth_header)
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT])
        # Optionally check response structure if implemented

    def test_sessions_unauthenticated(self):
        url = reverse('oidc:oidc-sessions')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_sessions_wrong_method(self):
        url = reverse('oidc:oidc-sessions')
        response = self.client.post(url)
        self.assertIn(response.status_code, [status.HTTP_405_METHOD_NOT_ALLOWED, status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED])

    def test_sessions_with_invalid_token(self):
        url = reverse('oidc:oidc-sessions')
        auth_header = 'Bearer invalidtoken'
        response = self.client.get(url, HTTP_AUTHORIZATION=auth_header)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_sessions_with_expired_token(self):
        # Create expired token
        expired_token = AccessToken.objects.create(
            user=self.user,
            token=generate_token(),
            application=self.application,
            expires=timezone.now() - timezone.timedelta(hours=1),
            scope='openid profile email',
        )
        url = reverse('oidc:oidc-sessions')
        auth_header = f'Bearer {expired_token.token}'
        response = self.client.get(url, HTTP_AUTHORIZATION=auth_header)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_sessions_with_missing_authorization_header(self):
        url = reverse('oidc:oidc-sessions')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_sessions_with_empty_authorization_header(self):
        url = reverse('oidc:oidc-sessions')
        response = self.client.get(url, HTTP_AUTHORIZATION='')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_sessions_with_malformed_authorization_header(self):
        url = reverse('oidc:oidc-sessions')
        response = self.client.get(url, HTTP_AUTHORIZATION='MalformedHeader')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
