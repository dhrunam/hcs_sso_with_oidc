from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from unittest.mock import patch, MagicMock
from apps.oidc.permissions import IsClientAuthenticated

class DummyView(APIView):
    permission_classes = [IsClientAuthenticated]
    def post(self, request):
        return Response({'ok': True})

class IsClientAuthenticatedTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = DummyView.as_view()

    @patch('oauth2_provider.models.Application')
    def test_basic_auth_success(self, MockApp):
        # Setup mock Application
        mock_app = MagicMock()
        mock_app.client_secret = 'secret123'
        MockApp.objects.get.return_value = mock_app
        # Encode credentials
        import base64
        creds = base64.b64encode(b'clientid:secret123').decode('utf-8')
        auth_header = f'Basic {creds}'
        req = self.factory.post('/oidc/token/', {}, HTTP_AUTHORIZATION=auth_header)
        request = Request(req)
        perm = IsClientAuthenticated()
        self.assertTrue(perm.has_permission(request, None))
        self.assertIs(request.client_app, mock_app)

    @patch('oauth2_provider.models.Application')
    def test_basic_auth_invalid_secret(self, MockApp):
        mock_app = MagicMock()
        mock_app.client_secret = 'secret123'
        MockApp.objects.get.return_value = mock_app
        import base64
        creds = base64.b64encode(b'clientid:wrongsecret').decode('utf-8')
        auth_header = f'Basic {creds}'
        req = self.factory.post('/oidc/token/', {}, HTTP_AUTHORIZATION=auth_header)
        request = Request(req)
        perm = IsClientAuthenticated()
        self.assertFalse(perm.has_permission(request, None))

    @patch('oauth2_provider.models.Application')
    def test_basic_auth_invalid_header(self, MockApp):
        req = self.factory.post('/oidc/token/', {}, HTTP_AUTHORIZATION='Basic invalidbase64')
        request = Request(req)
        perm = IsClientAuthenticated()
        self.assertFalse(perm.has_permission(request, None))

    @patch('oauth2_provider.models.Application')
    def test_post_body_credentials_success(self, MockApp):
        mock_app = MagicMock()
        mock_app.client_secret = 'secret123'
        MockApp.objects.get.return_value = mock_app
        data = {'client_id': 'clientid', 'client_secret': 'secret123'}
        req = self.factory.post('/oidc/token/', data, format='json')
        request = Request(req, parsers=[JSONParser()])
        perm = IsClientAuthenticated()
        self.assertTrue(perm.has_permission(request, None))
        self.assertIs(request.client_app, mock_app)

    @patch('oauth2_provider.models.Application')
    def test_post_body_missing_credentials(self, MockApp):
        req = self.factory.post('/oidc/token/', {}, format='json')
        request = Request(req, parsers=[JSONParser()])
        perm = IsClientAuthenticated()
        self.assertFalse(perm.has_permission(request, None))

    @patch('oauth2_provider.models.Application')
    def test_post_body_invalid_secret(self, MockApp):
        mock_app = MagicMock()
        mock_app.client_secret = 'secret123'
        MockApp.objects.get.return_value = mock_app
        data = {'client_id': 'clientid', 'client_secret': 'wrongsecret'}
        req = self.factory.post('/oidc/token/', data, format='json')
        request = Request(req, parsers=[JSONParser()])
        perm = IsClientAuthenticated()
        self.assertFalse(perm.has_permission(request, None))

    @patch('oauth2_provider.models.Application')
    def test_unknown_client_id(self, MockApp):
        MockApp.objects.get.side_effect = MockApp.DoesNotExist
        data = {'client_id': 'unknown', 'client_secret': 'secret'}
        req = self.factory.post('/oidc/token/', data, format='json')
        request = Request(req, parsers=[JSONParser()])
        perm = IsClientAuthenticated()
        self.assertFalse(perm.has_permission(request, None))
