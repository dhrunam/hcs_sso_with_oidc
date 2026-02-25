from django.contrib.auth.models import User
from django.urls import reverse
from django.test import override_settings
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.authtoken.models import Token
from unittest.mock import patch, Mock

from apps.core.models import Organization, Department
class LoginOptionsViewTests(APITestCase):
    def test_login_options_default_contains_local(self):
        url = reverse('users:login-options')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['local_login_enabled'])
        self.assertIn('options', response.data)
        self.assertTrue(any(opt['id'] == 'local' for opt in response.data['options']))

    @patch('apps.users.views.get_available_providers')
    @override_settings(OIDC_RP_CLIENT_ID='oidc-client-id', SAML_CONFIG={})
    def test_login_options_includes_social_oidc_saml(self, mock_providers):
        mock_providers.return_value = [('google-oauth2', 'Google')]

        url = reverse('users:login-options')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['social_login_enabled'])
        self.assertTrue(response.data['oidc_login_enabled'])
        self.assertTrue(response.data['saml_login_enabled'])
        option_ids = {opt['id'] for opt in response.data['options']}
        self.assertIn('google-oauth2', option_ids)
        self.assertIn('oidc', option_ids)
        self.assertIn('saml', option_ids)


class PublicUserInfoViewTests(APITestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name='TestOrg', domain='test.org')
        self.department = Department.objects.create(
            organization=self.organization,
            name='Engineering',
            code='ENG'
        )

    def test_public_user_info_active_user(self):
        user = User.objects.create_user(
            username='publicuser',
            email='public@example.com',
            first_name='Public',
            last_name='User',
            password='StrongPass123',
            is_active=True,
        )
        user.profile.department = self.department
        user.profile.job_title = 'Engineer'
        user.profile.save()

        url = reverse('users:public-user-info', kwargs={'user_id': user.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'publicuser')
        self.assertEqual(response.data['job_title'], 'Engineer')
        self.assertEqual(response.data['department'], 'Engineering')

    def test_public_user_info_inactive_user_returns_404(self):
        user = User.objects.create_user(
            username='inactiveuser',
            email='inactive@example.com',
            password='StrongPass123',
            is_active=False,
        )

        url = reverse('users:public-user-info', kwargs={'user_id': user.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['error'], 'User not found')


class VerifyEmailViewTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='verifyuser',
            email='verify@example.com',
            password='StrongPass123',
            is_active=True,
        )
        self.client.force_authenticate(user=self.user)

    def test_verify_email_success(self):
        self.user.profile.extra_data = {
            'email_verification_token': 'token-123',
            'email_verification_sent': '2026-02-25T00:00:00Z'
        }
        self.user.profile.email_verified = False
        self.user.profile.save()

        url = reverse('users:verify-email')
        response = self.client.post(url, {'token': 'token-123'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['email_verified'])
        self.user.profile.refresh_from_db()
        self.assertTrue(self.user.profile.email_verified)
        self.assertNotIn('email_verification_token', self.user.profile.extra_data or {})

    def test_verify_email_invalid_token(self):
        self.user.profile.extra_data = {'email_verification_token': 'token-abc'}
        self.user.profile.save()

        url = reverse('users:verify-email')
        response = self.client.post(url, {'token': 'wrong-token'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid verification token')


class PasswordResetViewsTests(APITestCase):
    @patch('apps.users.views.Token')
    @override_settings(DEBUG=True, FRONTEND_URL='http://localhost:3000')
    def test_password_reset_request_existing_user(self, mock_token):
        user = User.objects.create_user(
            username='resetuser',
            email='reset@example.com',
            password='StrongPass123',
            is_active=True,
        )

        token_obj = Mock()
        token_obj.key = 'mock-token-key'
        mock_token.objects.get_or_create.return_value = (token_obj, True)

        url = reverse('users:password-reset-request')
        response = self.client.post(url, {'email': user.email}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('reset_url', response.data)
        self.assertIn('/reset-password/', response.data['reset_url'])

    def test_password_reset_request_non_existing_user(self):
        url = reverse('users:password-reset-request')
        response = self.client.post(url, {'email': 'missing@example.com'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

    @patch('apps.users.views.Token')
    def test_password_reset_confirm_invalid_token(self, mock_token):
        does_not_exist = type('TokenDoesNotExist', (Exception,), {})
        mock_token.DoesNotExist = does_not_exist
        mock_token.objects.get.side_effect = does_not_exist()

        url = reverse('users:password-reset-confirm')
        response = self.client.post(
            url,
            {
                'token': 'invalid-token',
                'uid': '1',
                'new_password': 'NewStrongPass123',
                'confirm_password': 'NewStrongPass123'
            },
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid or expired reset token')


class UserProfileAndHealthViewTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='profileuser',
            email='profile@example.com',
            first_name='Profile',
            last_name='User',
            password='StrongPass123',
            is_active=True,
        )

    def test_user_profile_retrieve_includes_social_connections(self):
        self.client.force_authenticate(user=self.user)

        url = reverse('users:user-profile')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'profileuser')
        self.assertIn('social_connections', response.data)
        self.assertIsInstance(response.data['social_connections'], list)

    def test_health_check_returns_healthy(self):
        url = reverse('users:health-check')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'healthy')
        self.assertIn('database', response.data)
        self.assertIn('cache', response.data)
