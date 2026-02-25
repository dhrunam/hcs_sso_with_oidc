from django.test import TestCase
from django.contrib.auth.models import User
from apps.core.models import UserProfile, Organization, Department
from django.core.exceptions import ValidationError
from django.utils import timezone

class UserProfileModelTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name='TestOrg', domain='test.org')
        self.dept = Department.objects.create(organization=self.org, name='IT', code='IT')
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='pass')
        self.profile = self.user.profile  # Use the auto-created profile
        self.profile.department = self.dept
        self.profile.save()

    def test_profile_creation_and_str(self):
        profile = self.profile
        self.assertEqual(str(profile), f"{self.user.email} ({profile.identity_provider})")
        self.assertEqual(profile.organization, self.org)
        self.assertEqual(profile.full_name, self.user.get_full_name())

    def test_clean_external_id_with_local(self):
        profile = self.profile
        profile.identity_provider = 'local'
        profile.external_id = 'abc'
        with self.assertRaises(ValidationError):
            profile.clean()

    def test_clean_external_id_required_for_nonlocal(self):
        profile = self.profile
        profile.identity_provider = 'google'
        profile.external_id = ''
        with self.assertRaises(ValidationError):
            profile.clean()

    def test_clean_phone_number_format(self):
        profile = self.profile
        profile.phone_number = '+1 (234) 567-8900'
        profile.clean()
        self.assertEqual(profile.phone_number, '+12345678900')
        user2 = User.objects.create_user(username='testuser2', email='test2@example.com', password='pass')
        profile2 = user2.profile
        profile2.phone_number = '(234) 567-8900'
        profile2.clean()
        self.assertEqual(profile2.phone_number, '2345678900')

    def test_update_last_login(self):
        profile = self.profile
        profile.update_last_login()
        self.assertIsNotNone(profile.last_login_at)
        self.assertAlmostEqual(profile.last_login_at.timestamp(), timezone.now().timestamp(), delta=5)

    def test_unique_external_identity_constraint(self):
        profile = self.profile
        profile.identity_provider = 'google'
        profile.external_id = 'abc'
        profile.save()
        user2 = User.objects.create_user(username='testuser2', email='test2@example.com', password='pass')
        profile2 = user2.profile
        profile2.identity_provider = 'google'
        profile2.external_id = 'abc'
        with self.assertRaises(Exception):
            profile2.save()

    def test_employee_id_unique(self):
        profile = self.profile
        profile.employee_id = 'E123'
        profile.save()
        user2 = User.objects.create_user(username='testuser3', email='test3@example.com', password='pass')
        profile2 = user2.profile
        profile2.employee_id = 'E123'
        with self.assertRaises(Exception):
            profile2.save()

class OrganizationModelTests(TestCase):
    def test_organization_str_and_clean(self):
        org = Organization.objects.create(name='TestOrg', domain='  TEST.ORG  ')
        org.clean()
        self.assertEqual(org.domain, 'test.org')
        self.assertEqual(str(org), 'TestOrg')

    def test_organization_domain_unique(self):
        Organization.objects.create(name='Org1', domain='org1.com')
        with self.assertRaises(Exception):
            Organization.objects.create(name='Org2', domain='org1.com')

class DepartmentModelTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name='TestOrg', domain='test.org')

    def test_department_str_and_clean(self):
        dept = Department.objects.create(organization=self.org, name='IT', code=' it ', description='desc')
        dept.clean()
        self.assertEqual(dept.code, 'IT')
        self.assertEqual(str(dept), 'TestOrg - IT')

    def test_department_code_unique(self):
        Department.objects.create(organization=self.org, name='IT', code='IT')
        with self.assertRaises(Exception):
            Department.objects.create(organization=self.org, name='HR', code='IT')

    def test_department_name_unique_per_org(self):
        Department.objects.create(organization=self.org, name='IT', code='IT')
        org2 = Organization.objects.create(name='OtherOrg', domain='other.org')
        # Same name allowed in different org
        Department.objects.create(organization=org2, name='IT', code='IT2')
        # Same name not allowed in same org
        with self.assertRaises(Exception):
            Department.objects.create(organization=self.org, name='IT', code='IT3')
