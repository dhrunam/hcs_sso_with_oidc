import base64
import datetime
from django.test import TestCase, Client
from django.urls import reverse
from oauth2_provider.models import Application, AccessToken
from django.contrib.auth import get_user_model
from django.utils import timezone


class IntrospectionAuthTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='testuser', password='pass')

        # Create a confidential client application
        self.app = Application.objects.create(
            name='test-client',
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_id='test_client_id',
            client_secret='test_secret',
            user=self.user,
        )

        # Create an access token belonging to the app
        expires = timezone.now() + datetime.timedelta(hours=1)
        self.token = AccessToken.objects.create(
            user=self.user,
            scope='read write',
            expires=expires,
            token='tok_abc123',
            application=self.app,
        )

        self.client = Client()

    def test_introspect_with_valid_basic_auth(self):
        url = reverse('oidc:oidc-introspect')
        creds = f"{self.app.client_id}:{self.app.client_secret}"
        b64 = base64.b64encode(creds.encode()).decode()
        response = self.client.post(url, {'token': self.token.token}, HTTP_AUTHORIZATION=f'Basic {b64}')
        # Valid basic auth from the issuing client should allow introspection
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('active', data)

    def test_introspect_with_post_credentials(self):
        url = reverse('oidc:oidc-introspect')
        data = {
            'token': self.token.token,
            'client_id': self.app.client_id,
            'client_secret': self.app.client_secret,
        }
        response = self.client.post(url, data)
        # Valid client credentials in POST should allow introspection and return JSON with 'active' key
        self.assertEqual(response.status_code, 200)
        self.assertIn('active', response.json())

    def test_introspect_with_wrong_credentials(self):
        url = reverse('oidc:oidc-introspect')
        data = {'token': self.token.token, 'client_id': 'bad', 'client_secret': 'bad'}
        response = self.client.post(url, data)
        # Wrong credentials should be rejected by the permission class
        self.assertIn(response.status_code, (401, 403))
