"""
Unit tests for social authentication pipeline functions.
Tests cover data extraction, normalization, validation, and user profile creation.
"""

import pytest
from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.utils import timezone
from unittest.mock import Mock, patch, MagicMock
from apps.core.models import UserProfile
from apps.social.pipeline import (
    validate_social_auth,
    extract_and_normalize_data,
    create_or_update_user_profile,
    extract_user_data,
    validate_email_domain,
    get_provider_display_name,
)
from social_core.exceptions import AuthForbidden

User = get_user_model()


class TestProviderDisplayName(TestCase):
    """Test provider display name mapping"""
    
    def test_known_providers(self):
        """Test display names for known providers"""
        assert get_provider_display_name('google-oauth2') == 'Google'
        assert get_provider_display_name('facebook') == 'Facebook'
        assert get_provider_display_name('github') == 'GitHub'
        assert get_provider_display_name('microsoft-graph') == 'Microsoft'
        assert get_provider_display_name('linkedin') == 'LinkedIn'
    
    def test_unknown_provider(self):
        """Test fallback for unknown provider"""
        result = get_provider_display_name('custom-provider')
        assert 'custom' in result.lower()


class TestEmailDomainValidation(TestCase):
    """Test email domain validation logic"""
    
    def test_no_restrictions(self):
        """No restrictions when ALLOWED_DOMAINS is empty"""
        with patch('apps.social.pipeline.ALLOWED_EMAIL_DOMAINS', []):
            assert validate_email_domain('user@example.com', 'google-oauth2') is True
    
    def test_allowed_domain(self):
        """Allowed domain passes validation"""
        with patch('apps.social.pipeline.ALLOWED_EMAIL_DOMAINS', ['example.com', 'org.com']):
            assert validate_email_domain('user@example.com', 'google-oauth2') is True
    
    def test_disallowed_domain(self):
        """Disallowed domain fails validation"""
        with patch('apps.social.pipeline.ALLOWED_EMAIL_DOMAINS', ['example.com']):
            assert validate_email_domain('user@notallowed.com', 'google-oauth2') is False
    
    def test_no_email(self):
        """Empty email fails validation"""
        assert validate_email_domain('', 'google-oauth2') is False
        assert validate_email_domain(None, 'google-oauth2') is False


class TestExtractUserData(TestCase):
    """Test user data extraction from provider responses"""
    
    def test_google_extraction(self):
        """Extract data from Google response"""
        response = {
            'sub': 'google_123',
            'email': 'user@example.com',
            'given_name': 'John',
            'family_name': 'Doe',
            'picture': 'https://example.com/pic.jpg',
            'locale': 'en',
            'email_verified': True,
        }
        
        data = extract_user_data('google-oauth2', response)
        
        assert data['email'] == 'user@example.com'
        assert data['first_name'] == 'John'
        assert data['last_name'] == 'Doe'
        assert data['picture_url'] == 'https://example.com/pic.jpg'
        assert data['email_verified'] is True
        assert data['extra_data']['google_id'] == 'google_123'
    
    def test_microsoft_extraction(self):
        """Extract data from Microsoft response"""
        response = {
            'id': 'ms_123',
            'mail': 'user@company.com',
            'userPrincipalName': 'user@company.com',
            'displayName': 'John Doe',
            'givenName': 'John',
            'surname': 'Doe',
            'jobTitle': 'Engineer',
        }
        
        data = extract_user_data('microsoft-graph', response)
        
        assert data['email'] == 'user@company.com'
        assert data['first_name'] == 'John'
        assert data['last_name'] == 'Doe'
        assert data['extra_data']['job_title'] == 'Engineer'
        assert data['extra_data']['microsoft_id'] == 'ms_123'
    
    def test_github_extraction(self):
        """Extract data from GitHub response"""
        response = {
            'id': 12345,
            'login': 'johndoe',
            'name': 'John Doe',
            'email': 'john@example.com',
            'avatar_url': 'https://avatars.githubusercontent.com/u/12345',
            'company': 'Tech Corp',
            'location': 'San Francisco',
        }
        
        data = extract_user_data('github', response)
        
        assert data['email'] == 'john@example.com'
        assert data['full_name'] == 'John Doe'
        assert data['extra_data']['github_id'] == 12345
        assert data['extra_data']['company'] == 'Tech Corp'
    
    def test_linkedin_extraction(self):
        """Extract data from LinkedIn response (FIXED: no typo)"""
        response = {
            'id': 'linkedin_123',
            'email': 'user@example.com',
            'localizedFirstName': 'John',
            'localizedLastName': 'Doe',
            'headline': 'Software Engineer at Tech Corp',
            'industry': 'Technology',
        }
        
        data = extract_user_data('linkedin', response)
        
        # LinkedIn maps differently, this tests the fixed typo
        assert data['extra_data']['headline'] == 'Software Engineer at Tech Corp'
        assert data['extra_data']['industry'] == 'Technology'
    
    def test_oidc_extraction(self):
        """Extract data from generic OIDC response"""
        response = {
            'sub': 'oidc_user_123',
            'email': 'user@oidc.com',
            'name': 'John Doe',
            'given_name': 'John',
            'family_name': 'Doe',
            'email_verified': True,
            'picture': 'https://example.com/avatar.jpg',
            'locale': 'en_US',
            'zoneinfo': 'America/New_York',
        }
        
        data = extract_user_data('openid-connect', response)
        
        assert data['email'] == 'user@oidc.com'
        assert data['email_verified'] is True
        assert data['extra_data']['oidc_id'] == 'oidc_user_123'


class TestValidateSocialAuth(TestCase):
    """Test initial validation in auth pipeline"""
    
    def setUp(self):
        self.backend = Mock(name='google-oauth2')
        self.backend.name = 'google-oauth2'
    
    def test_valid_auth_passes(self):
        """Valid auth passes validation"""
        details = {'email': 'user@example.com'}
        response = {'email': 'user@example.com'}
        
        with patch('apps.social.pipeline.ALLOWED_EMAIL_DOMAINS', []):
            result = validate_social_auth(self.backend, details, response)
            assert result['details'] == details
    
    def test_forbidden_domain_raises(self):
        """Forbidden email domain raises AuthForbidden"""
        details = {'email': 'user@forbidden.com'}
        response = {'email': 'user@forbidden.com'}
        
        with patch('apps.social.pipeline.ALLOWED_EMAIL_DOMAINS', ['allowed.com']):
            with pytest.raises(AuthForbidden):
                validate_social_auth(self.backend, details, response)


class TestExtractAndNormalizeData(TestCase):
    """Test data extraction and normalization in pipeline"""
    
    def setUp(self):
        self.backend = Mock(name='google-oauth2')
        self.backend.name = 'google-oauth2'
    
    def test_data_normalization(self):
        """Data is normalized and extracted correctly"""
        details = {'email': 'user@example.com'}
        response = {
            'email': 'user@example.com',
            'given_name': 'John',
            'family_name': 'Doe',
            'picture': 'https://example.com/pic.jpg',
            'sub': 'google_123',
        }
        
        result = extract_and_normalize_data(
            self.backend, details, response
        )
        
        assert result['details']['email'] == 'user@example.com'
        assert result['details']['first_name'] == 'John'
        assert result['user_data']['picture_url'] == 'https://example.com/pic.jpg'
        assert result['backend_name'] == 'google-oauth2'


class TestCreateOrUpdateUserProfile(TestCase):
    """Test user profile creation and updates in pipeline"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.backend = Mock(name='google-oauth2')
        self.backend.name = 'google-oauth2'
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            first_name='Test'
        )
    
    def test_profile_creation(self):
        """New profile is created for user"""
        user_data = {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'locale': 'en',
            'timezone': 'UTC',
            'picture_url': 'https://example.com/pic.jpg',
            'extra_data': {'google_id': 'google_123'}
        }
        
        result = create_or_update_user_profile(
            strategy=Mock(),
            details={},
            backend=self.backend,
            user=self.user,
            user_data=user_data,
            backend_name='google-oauth2',
            response={'sub': 'google_123'},
            uid='google_123',
        )
        
        profile = UserProfile.objects.get(user=self.user)
        assert profile.identity_provider == 'google-oauth2'
        assert profile.external_id == 'google_123'
        assert profile.preferred_language == 'en'
        assert profile.timezone == 'UTC'
    
    def test_profile_update(self):
        """Existing profile is updated"""
        # Create initial profile
        profile = UserProfile.objects.create(
            user=self.user,
            identity_provider='google-oauth2',
            external_id='google_123'
        )
        
        user_data = {
            'email': 'test@example.com',
            'timezone': 'America/New_York',
            'extra_data': {}
        }
        
        result = create_or_update_user_profile(
            strategy=Mock(),
            details={},
            backend=self.backend,
            user=self.user,
            user_data=user_data,
            backend_name='google-oauth2',
            response={},
            uid='google_123',
        )
        
        profile.refresh_from_db()
        assert profile.timezone == 'America/New_York'
    
    def test_no_user_returns_none(self):
        """Returns None user when user is None"""
        result = create_or_update_user_profile(
            strategy=Mock(),
            details={},
            backend=self.backend,
            user=None,
            user_data={},
            backend_name='google-oauth2',
            response={},
        )
        
        assert result['user'] is None


class TestPipelineIntegration(TestCase):
    """Integration tests for pipeline functions working together"""
    
    def setUp(self):
        self.backend = Mock(name='google-oauth2')
        self.backend.name = 'google-oauth2'
        self.factory = RequestFactory()
    
    def test_full_pipeline_flow(self):
        """Test complete pipeline flow from validation to profile creation"""
        details = {'email': 'newuser@example.com'}
        response = {
            'sub': 'google_456',
            'email': 'newuser@example.com',
            'given_name': 'Jane',
            'family_name': 'Smith',
            'email_verified': True,
            'picture': 'https://example.com/jane.jpg',
        }
        
        # Step 1: Validate
        with patch('apps.social.pipeline.ALLOWED_EMAIL_DOMAINS', []):
            val_result = validate_social_auth(self.backend, details, response)
            assert val_result is not None
        
        # Step 2: Extract and normalize
        extract_result = extract_and_normalize_data(
            self.backend, val_result['details'], response
        )
        assert extract_result['user_data']['email'] == 'newuser@example.com'
        
        # Step 3: Create user and profile
        user = User.objects.create_user(
            username='janesmith',
            email='newuser@example.com',
            first_name='Jane',
            last_name='Smith'
        )
        
        profile_result = create_or_update_user_profile(
            strategy=Mock(),
            details=extract_result['details'],
            backend=self.backend,
            user=user,
            user_data=extract_result['user_data'],
            backend_name=extract_result['backend_name'],
            response=response,
            uid=response['sub'],
        )
        
        # Verify final state
        profile = UserProfile.objects.get(user=user)
        assert profile.identity_provider == 'google-oauth2'
        assert profile.external_id == 'google_456'
        assert profile.email_verified is True


# TODO: Add tests for:
# - create_social_connection_record
# - assign_default_groups_and_permissions
# - send_verification_email
# - Log/audit event creation
# - Error handling and edge cases
# - Social connection conflicts (user trying to link existing account)
