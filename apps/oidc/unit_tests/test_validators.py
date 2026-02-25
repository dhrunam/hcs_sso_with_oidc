from django.test import TestCase
from unittest.mock import MagicMock, patch
from apps.oidc.validators import CustomOAuth2Validator
from types import SimpleNamespace
from django.utils import timezone

class CustomOAuth2ValidatorTests(TestCase):
    def setUp(self):
        self.validator = CustomOAuth2Validator()
        self.user = MagicMock()
        self.user.is_authenticated = True
        self.user.id = 1
        self.user.username = 'testuser'
        self.user.first_name = 'Test'
        self.user.last_name = 'User'
        self.user.email = 'test@example.com'
        self.user.last_login = timezone.now()
        self.user.date_joined = timezone.now()
        self.user.groups.all.return_value = []

    def test_filter_scopes_by_user_groups(self):
        # User in API_READERS and API_ADMINS
        group1 = MagicMock(name='API_READERS')
        group1.name = 'API_READERS'
        group2 = MagicMock(name='API_ADMINS')
        group2.name = 'API_ADMINS'
        self.user.groups.all.return_value = [group1, group2]
        requested = ['openid', 'api.read', 'api.write', 'profile', 'email', 'offline_access']
        allowed = self.validator.filter_scopes_by_user_groups(self.user, requested)
        self.assertIn('api.read', allowed)
        self.assertIn('api.write', allowed)
        self.assertIn('openid', allowed)
        self.assertIn('profile', allowed)
        self.assertIn('email', allowed)
        self.assertIn('offline_access', allowed)

    @patch('apps.oidc.validators.CustomOAuth2Validator._get_user_profile')
    @patch('oauth2_provider.oauth2_validators.OAuth2Validator.finalize_id_token', return_value=None)
    def test_finalize_id_token_sets_aud_and_claims(self, mock_super, mock_profile):
        mock_profile.return_value = SimpleNamespace(identity_provider='test_idp')
        id_token = {}
        token = object()
        token_handler = object()
        request = SimpleNamespace()
        request.client = SimpleNamespace(client_id='client123', algorithm='RS256')
        request.user = self.user
        request.scopes = []
        request.nonce = None
        self.user.groups.values_list.return_value = [('API_READERS',), ('API_ADMINS',)]
        with patch('django.conf.settings', OAUTH2_PROVIDER={'OIDC_AUDIENCE': ['aud1']}):
            self.validator.finalize_id_token(id_token, token, token_handler, request)
        self.assertIn('aud', id_token)
        self.assertIn('groups', id_token)
        self.assertIn('identity_provider', id_token)
        self.assertEqual(id_token['identity_provider'], 'test_idp')

    @patch('apps.oidc.validators.CustomOAuth2Validator._get_user_profile')
    def test_get_additional_claims_profile_and_email(self, mock_profile):
        profile = SimpleNamespace(email_verified=True, identity_provider='test_idp', department=None, employee_id=None, job_title=None)
        mock_profile.return_value = profile
        self.user.groups.values_list.return_value = [('API_READERS',), ('API_ADMINS',)]
        request = SimpleNamespace()
        request.user = self.user
        request.scopes = ['profile', 'email']
        request.client = SimpleNamespace(client_id='client123')
        claims = self.validator.get_additional_claims(request)
        self.assertIn('name', claims)
        self.assertIn('email', claims)
        self.assertTrue(claims['email_verified'])
        self.assertIn('identity_provider', claims)
        self.assertIn('groups', claims)

    @patch('apps.oidc.validators.CustomOAuth2Validator._get_user_profile')
    def test_get_additional_claims_custom_org(self, mock_profile):
        org = SimpleNamespace(name='OrgName')
        dept = SimpleNamespace(code='DPT', organization=org)
        profile = SimpleNamespace(email_verified=True, identity_provider='test_idp', department=dept, employee_id='EID', job_title='Engineer')
        mock_profile.return_value = profile
        self.user.groups.values_list.return_value = [('API_READERS',)]
        request = SimpleNamespace()
        request.user = self.user
        request.scopes = ['custom', 'org']
        request.client = SimpleNamespace(client_id='client123')
        claims = self.validator.get_additional_claims(request)
        self.assertIn('organization', claims)
        self.assertIn('department', claims)
        self.assertIn('employee_id', claims)
        self.assertIn('job_title', claims)

    @patch('apps.oidc.utils.claims.get_userinfo_claims')
    def test_get_userinfo_claims_delegates(self, mock_utils):
        mock_utils.return_value = {'sub': '1'}
        request = SimpleNamespace()
        request.user = self.user
        request.scopes = ['openid']
        result = self.validator.get_userinfo_claims(request)
        self.assertEqual(result, {'sub': '1'})

    @patch('apps.oidc.validators.CustomOAuth2Validator._get_user_profile')
    @patch('oauth2_provider.oauth2_validators.OAuth2Validator.save_bearer_token', return_value=None)
    def test_save_bearer_token_adds_identity_provider(self, mock_super, mock_profile):
        profile = SimpleNamespace(identity_provider='test_idp')
        mock_profile.return_value = profile
        token = {}
        request = SimpleNamespace()
        request.user = self.user
        self.validator.save_bearer_token(token, request)
        self.assertEqual(token['identity_provider'], 'test_idp')
        mock_super.assert_called()

    @patch('oauth2_provider.oauth2_validators.OAuth2Validator.get_default_scopes', return_value=['profile'])
    def test_get_default_scopes_appends_openid(self, mock_super):
        scopes = self.validator.get_default_scopes('clientid', None)
        self.assertIn('openid', scopes)
        self.assertIn('profile', scopes)

    @patch('oauth2_provider.oauth2_validators.OAuth2Validator.validate_scopes', return_value=['openid', 'profile', 'email'])
    def test_validate_scopes_adds_profile_and_email(self, mock_super):
        # openid triggers profile/email
        request = SimpleNamespace()
        request.user = self.user
        self.user.is_authenticated = True
        validator = self.validator
        scopes = ['openid']
        result = validator.validate_scopes('clientid', scopes, None, request)
        self.assertIn('profile', scopes)
        self.assertIn('email', scopes)
