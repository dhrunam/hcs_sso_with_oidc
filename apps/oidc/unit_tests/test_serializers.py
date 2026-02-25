from django.test import TestCase
from unittest.mock import MagicMock, patch
from apps.oidc.serializers import (
    IntrospectionRequestSerializer,
    RevocationRequestSerializer,
    ClientRegistrationSerializer,
)
from oauth2_provider.models import Application

class IntrospectionRequestSerializerTests(TestCase):
    def test_valid_credentials(self):
        from oauth2_provider.models import Application
        app = Application.objects.create(
            name='TestApp',
            client_id='cid',
            client_secret='secret',
            user=None,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            redirect_uris='http://localhost',
            hash_client_secret=False,
        )
        data = {
            'token': 'tok',
            'token_type_hint': 'access_token',
            'client_id': 'cid',
            'client_secret': 'secret',
        }
        serializer = IntrospectionRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data['application'], app)

    @patch('apps.oidc.serializers.Application')
    def test_invalid_credentials(self, mock_app):
        mock_app.objects.get.side_effect = Application.DoesNotExist
        data = {
            'token': 'tok',
            'token_type_hint': 'access_token',
            'client_id': 'cid',
            'client_secret': 'wrong',
        }
        serializer = IntrospectionRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())

class RevocationRequestSerializerTests(TestCase):
    def test_valid_data(self):
        data = {
            'token': 'tok',
            'token_type_hint': 'refresh_token',
            'client_id': 'cid',
            'client_secret': 'secret',
        }
        serializer = RevocationRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_missing_fields(self):
        data = {'token': 'tok'}
        serializer = RevocationRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())

class ClientRegistrationSerializerTests(TestCase):
    @patch('apps.oidc.serializers.Application')
    def test_valid_registration(self, mock_app):
        mock_app.objects.create.return_value = MagicMock()
        data = {
            'client_name': 'Test Client',
            'redirect_uris': ['http://localhost/callback'],
            'grant_types': ['authorization_code'],
            'response_types': ['code'],
            'application_type': 'web',
            'token_endpoint_auth_method': 'client_secret_basic',
            'scope': 'openid profile email',
        }
        serializer = ClientRegistrationSerializer(data=data, context={'request': MagicMock()})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        instance = serializer.save()
        mock_app.objects.create.assert_called()

    def test_missing_required_fields(self):
        data = {'client_name': 'Test Client'}
        serializer = ClientRegistrationSerializer(data=data, context={'request': MagicMock()})
        self.assertFalse(serializer.is_valid())
