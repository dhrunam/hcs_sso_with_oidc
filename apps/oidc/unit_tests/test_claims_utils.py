from django.test import TestCase
from unittest.mock import MagicMock, patch
from apps.oidc.utils import claims

class ClaimsUtilsTests(TestCase):
    def setUp(self):
        self.user = MagicMock()
        self.user.id = 1
        self.user.first_name = 'John'
        self.user.last_name = 'Doe'
        self.user.username = 'johndoe'
        self.user.email = 'john@example.com'
        self.user.last_login = None
        self.user.date_joined = MagicMock()
        self.user.date_joined.timestamp.return_value = 1234567890

        self.profile = MagicMock()
        self.profile.avatar = MagicMock()
        self.profile.avatar.url = '/media/avatar.png'
        self.profile.email_verified = True
        self.profile.phone_number = '+1234567890'
        self.profile.identity_provider = 'local'
        self.profile.department = MagicMock()
        self.profile.department.organization = MagicMock()
        self.profile.department.organization.name = 'Org'
        self.profile.department.organization.domain = 'org.com'
        self.profile.department.code = 'D01'
        self.profile.department.name = 'Dept'
        self.profile.employee_id = 'E123'
        self.profile.job_title = 'Engineer'
        self.profile.preferred_language = 'en-US'
        self.profile.timezone = 'Asia/Kolkata'

    @patch('apps.oidc.utils.claims.get_user_profile')
    def test_get_standard_profile_claims(self, mock_get_user_profile):
        mock_get_user_profile.return_value = self.profile
        request = MagicMock()
        request.build_absolute_uri.return_value = 'http://testserver/media/avatar.png'
        result = claims.get_standard_profile_claims(self.user, include_picture_url=request)
        self.assertEqual(result['name'], 'John Doe')
        self.assertEqual(result['preferred_username'], 'johndoe')
        self.assertEqual(result['updated_at'], 1234567890)
        self.assertEqual(result['picture'], 'http://testserver/media/avatar.png')

    @patch('apps.oidc.utils.claims.get_user_profile')
    def test_get_email_claims(self, mock_get_user_profile):
        mock_get_user_profile.return_value = self.profile
        result = claims.get_email_claims(self.user)
        self.assertEqual(result['email'], 'john@example.com')
        self.assertTrue(result['email_verified'])

    def test_get_phone_claims(self):
        result = claims.get_phone_claims(self.profile)
        self.assertEqual(result['phone_number'], '+1234567890')
        self.assertFalse(result['phone_number_verified'])

    def test_get_address_claims(self):
        # No address fields, should return empty dict
        result = claims.get_address_claims(self.profile)
        self.assertEqual(result, {})

    def test_get_organization_claims(self):
        result = claims.get_organization_claims(self.profile)
        self.assertEqual(result['identity_provider'], 'local')
        self.assertEqual(result['organization'], 'Org')
        self.assertEqual(result['organization_domain'], 'org.com')
        self.assertEqual(result['department'], 'D01')
        self.assertEqual(result['department_name'], 'Dept')
        self.assertEqual(result['employee_id'], 'E123')
        self.assertEqual(result['job_title'], 'Engineer')

    def test_get_locale_claims(self):
        result = claims.get_locale_claims(self.profile)
        self.assertEqual(result['locale'], 'en-US')
        self.assertEqual(result['zoneinfo'], 'Asia/Kolkata')
