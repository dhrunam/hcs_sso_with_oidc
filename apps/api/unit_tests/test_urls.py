from django.test import SimpleTestCase
from django.urls import reverse, resolve

from apps.api import views


class ApiUrlsTests(SimpleTestCase):
    def test_api_root_url(self):
        path = reverse('api:api-root')
        self.assertEqual(path, '/api/')
        self.assertEqual(resolve(path).func.view_class, views.APIRootView)

    def test_health_check_url(self):
        path = reverse('api:health-check')
        self.assertEqual(path, '/api/health/')
        self.assertEqual(resolve(path).func.view_class, views.HealthCheckView)

    def test_system_info_url(self):
        path = reverse('api:system-info')
        self.assertEqual(path, '/api/system/info/')
        self.assertEqual(resolve(path).func.view_class, views.SystemInfoView)

    def test_metrics_url(self):
        path = reverse('api:metrics')
        self.assertEqual(path, '/api/metrics/')
        self.assertEqual(resolve(path).func.view_class, views.MetricsView)

    def test_client_register_url(self):
        path = reverse('api:client-register')
        self.assertEqual(path, '/api/clients/register/')
        self.assertEqual(resolve(path).func.view_class, views.ClientRegistrationView)

    def test_client_list_url(self):
        path = reverse('api:client-list')
        self.assertEqual(path, '/api/clients/')
        self.assertEqual(resolve(path).func.view_class, views.ClientManagementView)

    def test_client_detail_url(self):
        path = reverse('api:client-detail', kwargs={'client_id': 'abc123'})
        self.assertEqual(path, '/api/clients/abc123/')
        self.assertEqual(resolve(path).func.view_class, views.ClientManagementView)

    def test_robots_txt_url(self):
        path = reverse('api:robots-txt')
        self.assertEqual(path, '/api/robots.txt')
        self.assertEqual(resolve(path).func, views.robots_txt)

    def test_security_txt_url(self):
        path = reverse('api:security-txt')
        self.assertEqual(path, '/api/.well-known/security.txt')
        self.assertEqual(resolve(path).func, views.security_txt)
