from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework import status
from oauth2_provider.models import Application, AccessToken
from oauthlib.common import generate_token
from django.utils import timezone

User = get_user_model()

class OIDCUserInfoViewTests(APITestCase):
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

    def test_userinfo_authenticated(self):
        url = reverse('oidc:oidc-userinfo')
        auth_header = f'Bearer {self.access_token.token}'
        response = self.client.get(url, HTTP_AUTHORIZATION=auth_header)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sub', response.data)
        self.assertEqual(response.data['sub'], str(self.user.id))
        self.assertIn('email', response.data)
        self.assertEqual(response.data['email'], self.user.email)
        self.assertIn('groups', response.data)
        self.assertIn('API_READERS', response.data['groups'])

    def test_userinfo_unauthenticated(self):
        url = reverse('oidc:oidc-userinfo')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
