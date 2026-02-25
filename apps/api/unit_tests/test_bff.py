from unittest.mock import Mock, patch

import requests
from django.test import TestCase, RequestFactory, override_settings
from rest_framework import status
from rest_framework.test import APIRequestFactory

from apps.api.bff import (
    exchange_authorization_code_for_tokens,
    refresh_access_token,
    set_refresh_token_cookie,
    clear_refresh_token_cookie,
    BFFLoginView,
    BFFTokenRefreshView,
    BFFLogoutView,
    BFFAuthViewSet,
)


@override_settings(
    SSO_TOKEN_URL='http://localhost:8000/o/token/',
    BFF_CLIENT_ID='bff-client-id',
    BFF_CLIENT_SECRET='bff-client-secret',
    SECURE_COOKIE_SECURE=False,
    SECURE_COOKIE_SAMESITE='Lax',
)
class BFFHelperTests(TestCase):
    def test_exchange_authorization_code_for_tokens_success(self):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            'access_token': 'access-1',
            'refresh_token': 'refresh-1',
            'expires_in': 3600,
            'token_type': 'Bearer',
        }

        with patch('apps.api.views.bff.requests.post', return_value=mock_response) as mock_post:
            result = exchange_authorization_code_for_tokens('auth-code', 'verifier', 'http://localhost/callback')

        self.assertEqual(result['access_token'], 'access-1')
        mock_post.assert_called_once()

    def test_exchange_authorization_code_for_tokens_failure_raises(self):
        with patch('apps.api.views.bff.requests.post', side_effect=requests.RequestException('boom')):
            with self.assertRaises(requests.RequestException):
                exchange_authorization_code_for_tokens('auth-code', 'verifier', 'http://localhost/callback')

    def test_refresh_access_token_success(self):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            'access_token': 'access-2',
            'refresh_token': 'refresh-2',
            'expires_in': 3600,
            'token_type': 'Bearer',
        }

        with patch('apps.api.views.bff.requests.post', return_value=mock_response):
            result = refresh_access_token('refresh-1')

        self.assertEqual(result['access_token'], 'access-2')

    def test_cookie_set_and_clear_helpers(self):
        from django.http import JsonResponse

        response = JsonResponse({'ok': True})
        set_refresh_token_cookie(response, 'refresh-cookie', 120)
        self.assertIn('refresh_token', response.cookies)

        clear_refresh_token_cookie(response)
        self.assertIn('refresh_token', response.cookies)


@override_settings(
    SSO_TOKEN_URL='http://localhost:8000/o/token/',
    BFF_CLIENT_ID='bff-client-id',
    BFF_CLIENT_SECRET='bff-client-secret',
    SECURE_COOKIE_SECURE=False,
    SECURE_COOKIE_SAMESITE='Lax',
    SSO_REVOKE_URL='http://localhost:8000/o/revoke_token/',
)
class BFFClassBasedViewTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_bff_login_view_invalid_json(self):
        request = self.factory.post('/api/auth/login/sso', data='not-json', content_type='application/json')
        response = BFFLoginView.as_view()(request)

        self.assertEqual(response.status_code, 400)

    def test_bff_login_view_missing_fields(self):
        request = self.factory.post('/api/auth/login/sso', data='{}', content_type='application/json')
        response = BFFLoginView.as_view()(request)

        self.assertEqual(response.status_code, 400)

    @patch('apps.api.views.bff.exchange_authorization_code_for_tokens')
    def test_bff_login_view_success_sets_cookie(self, mock_exchange):
        mock_exchange.return_value = {
            'access_token': 'access-token',
            'refresh_token': 'refresh-token',
            'expires_in': 3600,
            'token_type': 'Bearer',
        }

        payload = '{"authorization_code":"abc","code_verifier":"ver","redirect_uri":"http://localhost/callback"}'
        request = self.factory.post('/api/auth/login/sso', data=payload, content_type='application/json')
        response = BFFLoginView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertIn('refresh_token', response.cookies)

    def test_bff_refresh_view_without_cookie(self):
        request = self.factory.post('/api/auth/refresh/', data='{}', content_type='application/json')
        request.COOKIES = {}

        response = BFFTokenRefreshView.as_view()(request)
        self.assertEqual(response.status_code, 401)

    @patch('apps.api.views.bff.refresh_access_token')
    def test_bff_refresh_view_success(self, mock_refresh):
        mock_refresh.return_value = {
            'access_token': 'new-access',
            'refresh_token': 'new-refresh',
            'expires_in': 3600,
            'token_type': 'Bearer',
        }

        request = self.factory.post('/api/auth/refresh/', data='{}', content_type='application/json')
        request.COOKIES = {'refresh_token': 'old-refresh'}

        response = BFFTokenRefreshView.as_view()(request)
        self.assertEqual(response.status_code, 200)
        self.assertIn('refresh_token', response.cookies)

    @patch('apps.api.views.bff.requests.post')
    def test_bff_logout_view_success(self, mock_post):
        request = self.factory.post('/api/auth/logout/', data='{}', content_type='application/json')
        request.COOKIES = {'refresh_token': 'rt-1'}

        response = BFFLogoutView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        mock_post.assert_called_once()
        self.assertIn('refresh_token', response.cookies)


@override_settings(
    SSO_TOKEN_URL='http://localhost:8000/o/token/',
    BFF_CLIENT_ID='bff-client-id',
    BFF_CLIENT_SECRET='bff-client-secret',
    SECURE_COOKIE_SECURE=False,
    SECURE_COOKIE_SAMESITE='Lax',
)
class BFFViewSetTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def test_viewset_login_validation_error(self):
        view = BFFAuthViewSet.as_view({'post': 'login'})
        request = self.factory.post('/api/auth/login/', {}, format='json')

        response = view(request)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_viewset_refresh_without_cookie(self):
        view = BFFAuthViewSet.as_view({'post': 'refresh'})
        request = self.factory.post('/api/auth/refresh/', {}, format='json')
        request.COOKIES = {}

        response = view(request)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('apps.api.views.bff.requests.post')
    def test_viewset_logout_success(self, mock_post):
        view = BFFAuthViewSet.as_view({'post': 'logout'})
        request = self.factory.post('/api/auth/logout/', {}, format='json')
        request.COOKIES = {'refresh_token': 'rt-1'}

        response = view(request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('refresh_token', response.cookies)
