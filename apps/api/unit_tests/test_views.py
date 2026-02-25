from django.contrib.auth.models import User
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from oauth2_provider.models import Application
from unittest.mock import patch, Mock


class APIRootAndPublicViewsTests(APITestCase):
    def test_api_root_returns_expected_structure(self):
        response = self.client.get(reverse('api:api-root'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('name', response.data)
        self.assertIn('endpoints', response.data)
        self.assertIn('authentication', response.data['endpoints'])

    def test_robots_txt(self):
        response = self.client.get(reverse('api:robots-txt'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Disallow: /admin/', response.content.decode())

    def test_security_txt(self):
        response = self.client.get(reverse('api:security-txt'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Contact: mailto:', response.content.decode())

    @patch('apps.api.views.HealthCheckView._get_system_info')
    def test_health_check(self, mock_system_info):
        mock_system_info.return_value = {'system': {'status': 'partial'}}
        response = self.client.get(reverse('api:health-check'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(response.data.get('status'), ['healthy', 'degraded'])
        self.assertIn('database', response.data)
        self.assertIn('cache', response.data)


class SystemAndMetricsViewTests(APITestCase):
    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='adminapi',
            email='adminapi@example.com',
            password='StrongPass123',
            is_staff=True,
            is_superuser=True,
        )
        self.normal_user = User.objects.create_user(
            username='normalapi',
            email='normalapi@example.com',
            password='StrongPass123',
            is_staff=False,
        )

    def test_system_info_requires_admin(self):
        self.client.force_authenticate(user=self.normal_user)

        response = self.client.get(reverse('api:system-info'))

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch('apps.api.views.SystemInfoView._get_django_version', return_value='5.2.0', create=True)
    def test_system_info_admin_success(self, _mock_version):
        self.client.force_authenticate(user=self.admin_user)

        response = self.client.get(reverse('api:system-info'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('service', response.data)
        self.assertIn('django', response.data)
        self.assertIn('authentication', response.data)

    def test_metrics_requires_admin(self):
        self.client.force_authenticate(user=self.normal_user)

        response = self.client.get(reverse('api:metrics'))

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_metrics_admin_success(self):
        self.client.force_authenticate(user=self.admin_user)

        response = self.client.get(reverse('api:metrics'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sso_users_total', response.content.decode())


class ClientManagementViewTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username='clientowner',
            email='owner@example.com',
            password='StrongPass123',
            is_staff=False,
        )
        self.other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='StrongPass123',
            is_staff=False,
        )

        self.owner_app = Application.objects.create(
            name='Owner App',
            client_id='owner-client-id',
            client_secret='owner-secret',
            user=self.owner,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            redirect_uris='http://localhost/callback',
            hash_client_secret=False,
        )

    def test_client_list_requires_authentication(self):
        response = self.client.get(reverse('api:client-list'))

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('apps.api.views.ClientRegistrationSerializer')
    def test_client_list_returns_only_own_clients(self, mock_serializer):
        Application.objects.create(
            name='Other App',
            client_id='other-client-id',
            client_secret='other-secret',
            user=self.other_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            redirect_uris='http://localhost/other',
            hash_client_secret=False,
        )

        serializer_instance = Mock()
        serializer_instance.data = [{'client_id': self.owner_app.client_id}]
        mock_serializer.return_value = serializer_instance

        self.client.force_authenticate(user=self.owner)
        response = self.client.get(reverse('api:client-list'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['clients'][0]['client_id'], self.owner_app.client_id)

    def test_client_detail_for_other_users_client_returns_404(self):
        other_app = Application.objects.create(
            name='Other App',
            client_id='other-client-id-2',
            client_secret='other-secret-2',
            user=self.other_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            redirect_uris='http://localhost/other2',
            hash_client_secret=False,
        )

        self.client.force_authenticate(user=self.owner)
        response = self.client.get(reverse('api:client-detail', kwargs={'client_id': other_app.client_id}))

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    @patch('apps.api.views.ClientRegistrationSerializer')
    def test_client_detail_for_owner_success(self, mock_serializer):
        serializer_instance = Mock()
        serializer_instance.data = {'client_id': self.owner_app.client_id}
        mock_serializer.return_value = serializer_instance

        self.client.force_authenticate(user=self.owner)

        response = self.client.get(reverse('api:client-detail', kwargs={'client_id': self.owner_app.client_id}))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['client_id'], self.owner_app.client_id)

    def test_client_delete_for_owner_success(self):
        self.client.force_authenticate(user=self.owner)

        response = self.client.delete(reverse('api:client-detail', kwargs={'client_id': self.owner_app.client_id}))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['client_id'], self.owner_app.client_id)
        self.assertFalse(Application.objects.filter(client_id=self.owner_app.client_id).exists())
