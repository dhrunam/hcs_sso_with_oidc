from django.test import TestCase, override_settings
from django.contrib.auth.models import User, Group
from django.db.models.signals import post_save, post_delete, pre_delete, m2m_changed
from unittest.mock import patch, MagicMock
from apps.core.models import UserProfile, Department, Organization
from apps.social.models import SocialConnection, SocialLoginEvent
from apps.users import signals
from django.conf import settings

class UserSignalsTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name='TestOrg', domain='test.org')
        self.dept = Department.objects.create(organization=self.org, name='IT', code='IT')
        self.user = User.objects.create_user(username='signaluser', email='signaluser@example.com', password='pass')
        self.user.profile.department = self.dept
        self.user.profile.save()

    def test_handle_user_creation_creates_profile_and_assigns_group(self):
        Group.objects.get_or_create(name='API_READERS')
        user = User.objects.create_user(username='newuser', email='newuser@example.com', password='pass')
        profile = UserProfile.objects.get(user=user)
        self.assertEqual(profile.identity_provider, 'local')
        self.assertIn('API_READERS', list(user.groups.values_list('name', flat=True)))

    def test_handle_user_creation_email_update_marks_unverified(self):
        self.user.email = 'changed@example.com'
        self.user.save(update_fields=['email'])
        self.user.profile.refresh_from_db()
        self.assertFalse(self.user.profile.email_verified)

    def test_handle_user_creation_activation_event(self):
        self.user.is_active = False
        self.user.save(update_fields=['is_active'])
        event = SocialLoginEvent.objects.filter(user=self.user, extra_data__action__startswith='user_').last()
        self.assertIsNotNone(event)
        self.assertIn('user_deactivated', event.extra_data['action'])

    def test_handle_profile_update_sets_default_avatar(self):
        with override_settings(DEFAULT_AVATAR_URL='http://example.com/avatar.png'):
            profile = self.user.profile
            profile.avatar = None
            profile.save()
            profile.refresh_from_db()
            self.assertIn('default_avatar', profile.extra_data)

    def test_handle_user_group_changes(self):
        group = Group.objects.create(name='TestGroup')
        m2m_changed.send(sender=User.groups.through, instance=self.user, action='post_add', pk_set={group.pk})
        # No assertion, just ensure no error

    def test_handle_user_deletion_and_cleanup(self):
        user = User.objects.create_user(username='todelete', email='todelete@example.com', password='pass')
        user_id = user.id
        user.delete()
        self.assertFalse(User.objects.filter(id=user_id).exists())
        # No assertion for cleanup, just ensure no error

    @patch('apps.users.signals.send_mail')
    def test_send_email_verification(self, mock_send_mail):
        signals.send_email_verification(self.user)
        self.user.profile.refresh_from_db()
        self.assertIn('email_verification_token', self.user.profile.extra_data)
        self.assertTrue(mock_send_mail.called)

    @patch('apps.users.signals.send_mail')
    def test_send_welcome_email_sync(self, mock_send_mail):
        signals.send_welcome_email_sync(self.user)
        self.assertTrue(mock_send_mail.called)

    def test_register_signals(self):
        # Just ensure no error
        signals.register_signals()
