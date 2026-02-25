from django.test import TestCase
from django.contrib.auth.models import User, Group
from apps.core.models import Organization, Department, UserProfile
from apps.users.serializers import (
    OrganizationSerializer, DepartmentSerializer, UserProfileSerializer,
    UserMinimalSerializer, UserSerializer, UserCreateSerializer, UserUpdateSerializer,
    AdminUserUpdateSerializer, PasswordChangeSerializer, PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer, UserBulkUpdateSerializer, UserStatsSerializer
)
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.test import APIRequestFactory
from django.conf import settings

class OrganizationSerializerTests(TestCase):
    def test_organization_serializer_valid(self):
        org = Organization.objects.create(name='TestOrg', domain='test.org')
        data = OrganizationSerializer(org).data
        self.assertEqual(data['name'], 'TestOrg')
        self.assertEqual(data['domain'], 'test.org')

    def test_organization_serializer_invalid_domain(self):
        serializer = OrganizationSerializer(data={'name': 'Org', 'domain': 'bad_domain'})
        self.assertFalse(serializer.is_valid())
        self.assertIn('domain', serializer.errors)

class DepartmentSerializerTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name='TestOrg', domain='test.org')

    def test_department_serializer_valid(self):
        dept = Department.objects.create(organization=self.org, name='IT', code='IT')
        data = DepartmentSerializer(dept).data
        self.assertEqual(data['name'], 'IT')
        self.assertEqual(data['organization'], self.org.id)

    def test_department_serializer_invalid_code(self):
        serializer = DepartmentSerializer(data={'name': 'IT', 'code': 'bad code', 'organization': self.org.id})
        self.assertFalse(serializer.is_valid())
        self.assertIn('code', serializer.errors)

class UserProfileSerializerTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name='TestOrg', domain='test.org')
        self.dept = Department.objects.create(organization=self.org, name='IT', code='IT')
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='pass')
        self.profile = self.user.profile
        self.profile.department = self.dept
        self.profile.save()

    def test_userprofile_serializer(self):
        data = UserProfileSerializer(self.profile).data
        self.assertEqual(data['department'], self.dept.id)
        self.assertEqual(data['organization']['id'], self.org.id)

    def test_userprofile_serializer_invalid_phone(self):
        self.profile.phone_number = 'badphone'
        serializer = UserProfileSerializer(self.profile)
        with self.assertRaises(DRFValidationError):
            serializer.validate_phone_number('badphone')

class UserMinimalSerializerTests(TestCase):
    def test_user_minimal_serializer(self):
        user = User.objects.create_user(username='mini', email='mini@example.com', password='pass')
        data = UserMinimalSerializer(user).data
        self.assertEqual(data['username'], 'mini')
        self.assertEqual(data['email'], 'mini@example.com')

class UserSerializerTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='full', email='full@example.com', password='pass')

    def test_user_serializer(self):
        data = UserSerializer(self.user).data
        self.assertEqual(data['username'], 'full')
        self.assertIn('profile', data)
        self.assertIn('groups', data)
        self.assertIn('permissions', data)

class UserCreateSerializerTests(TestCase):
    def test_user_create_serializer_valid(self):
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': 'StrongPass123',
            'password2': 'StrongPass123',
            'profile': {'employee_id': 'EMP001'}
        }
        serializer = UserCreateSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        user = serializer.save()
        self.assertEqual(user.username, 'newuser')
        user.refresh_from_db()
        user.profile.refresh_from_db()
        self.assertEqual(user.profile.employee_id, 'EMP001')

    def test_user_create_serializer_password_mismatch(self):
        data = {
            'username': 'baduser',
            'email': 'baduser@example.com',
            'first_name': 'Bad',
            'last_name': 'User',
            'password': 'StrongPass123',
            'password2': 'WrongPass123',
        }
        serializer = UserCreateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)

class PasswordChangeSerializerTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='changepass', email='changepass@example.com', password='oldpass123')
        self.factory = APIRequestFactory()
        self.request = self.factory.post('/fake-url/')
        self.request.user = self.user

    def test_password_change_valid(self):
        serializer = PasswordChangeSerializer(data={
            'old_password': 'oldpass123',
            'new_password': 'Newpass123',
            'confirm_password': 'Newpass123',
        }, context={'request': self.request})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('Newpass123'))

    def test_password_change_mismatch(self):
        serializer = PasswordChangeSerializer(data={
            'old_password': 'oldpass123',
            'new_password': 'Newpass123',
            'confirm_password': 'Wrongpass',
        }, context={'request': self.request})
        self.assertFalse(serializer.is_valid())
        self.assertIn('new_password', serializer.errors)

    def test_password_change_wrong_old(self):
        serializer = PasswordChangeSerializer(data={
            'old_password': 'wrongold',
            'new_password': 'Newpass123',
            'confirm_password': 'Newpass123',
        }, context={'request': self.request})
        self.assertFalse(serializer.is_valid())
        self.assertIn('old_password', serializer.errors)
