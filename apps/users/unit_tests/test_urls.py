from django.test import SimpleTestCase
from django.urls import reverse, resolve

from apps.users import views


class UsersUrlsTests(SimpleTestCase):
    def test_user_logout_url(self):
        path = reverse('users:user-logout')
        self.assertEqual(path, '/api/users/logout/')
        self.assertEqual(resolve(path).func.view_class, views.UserLogoutView)

    def test_user_register_url(self):
        path = reverse('users:user-register')
        self.assertEqual(path, '/api/users/register/')
        self.assertEqual(resolve(path).func.view_class, views.UserRegistrationView)

    def test_user_register_form_url(self):
        path = reverse('users:user-register-form')
        self.assertEqual(path, '/api/users/register-form/')
        self.assertEqual(resolve(path).func.view_class, views.UserRegistrationFormView)

    def test_user_profile_url(self):
        path = reverse('users:user-profile')
        self.assertEqual(path, '/api/users/profile/')
        self.assertEqual(resolve(path).func.view_class, views.UserProfileView)

    def test_password_change_url(self):
        path = reverse('users:password-change')
        self.assertEqual(path, '/api/users/password/change/')
        self.assertEqual(resolve(path).func.view_class, views.PasswordChangeView)

    def test_password_reset_request_url(self):
        path = reverse('users:password-reset-request')
        self.assertEqual(path, '/api/users/password/reset/request/')
        self.assertEqual(resolve(path).func.view_class, views.PasswordResetRequestView)

    def test_password_reset_confirm_url(self):
        path = reverse('users:password-reset-confirm')
        self.assertEqual(path, '/api/users/password/reset/confirm/')
        self.assertEqual(resolve(path).func.view_class, views.PasswordResetConfirmView)

    def test_verify_email_url(self):
        path = reverse('users:verify-email')
        self.assertEqual(path, '/api/users/verify-email/')
        self.assertEqual(resolve(path).func.view_class, views.VerifyEmailView)

    def test_login_options_url(self):
        path = reverse('users:login-options')
        self.assertEqual(path, '/api/users/login-options/')
        self.assertEqual(resolve(path).func.view_class, views.LoginOptionsView)

    def test_public_user_info_url(self):
        path = reverse('users:public-user-info', kwargs={'user_id': 123})
        self.assertEqual(path, '/api/users/123/public/')
        self.assertEqual(resolve(path).func.view_class, views.PublicUserInfoView)

    def test_health_check_url(self):
        path = reverse('users:health-check')
        self.assertEqual(path, '/api/users/health/')
        self.assertEqual(resolve(path).func, views.health_check)

    def test_admin_user_stats_url(self):
        path = reverse('users:admin-user-stats')
        self.assertEqual(path, '/api/users/admin/users/stats/')
        self.assertEqual(resolve(path).func.view_class, views.AdminUserStatsView)

    def test_admin_user_search_url(self):
        path = reverse('users:admin-user-search')
        self.assertEqual(path, '/api/users/admin/users/search/')
        self.assertEqual(resolve(path).func.view_class, views.AdminUserSearchView)

    def test_admin_user_router_urls(self):
        list_path = reverse('users:admin-users-list')
        detail_path = reverse('users:admin-users-detail', kwargs={'pk': 1})

        self.assertEqual(list_path, '/api/users/admin/users/')
        self.assertEqual(detail_path, '/api/users/admin/users/1/')
        self.assertEqual(resolve(list_path).func.cls, views.AdminUserViewSet)
        self.assertEqual(resolve(detail_path).func.cls, views.AdminUserViewSet)

    def test_admin_user_action_urls(self):
        bulk_update_path = reverse('users:admin-users-bulk-update')
        activate_path = reverse('users:admin-users-activate', kwargs={'pk': 1})
        reset_password_path = reverse('users:admin-users-reset-password', kwargs={'pk': 1})

        self.assertEqual(bulk_update_path, '/api/users/admin/users/bulk_update/')
        self.assertEqual(activate_path, '/api/users/admin/users/1/activate/')
        self.assertEqual(reset_password_path, '/api/users/admin/users/1/reset_password/')

        self.assertEqual(resolve(bulk_update_path).func.cls, views.AdminUserViewSet)
        self.assertEqual(resolve(activate_path).func.cls, views.AdminUserViewSet)
        self.assertEqual(resolve(reset_password_path).func.cls, views.AdminUserViewSet)
