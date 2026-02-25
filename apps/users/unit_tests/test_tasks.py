from django.test import TestCase
from django.contrib.auth.models import User
from django.conf import settings
from unittest.mock import patch

from apps.users.tasks import send_welcome_email, send_password_reset_email


class UserTasksTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='taskuser',
            email='taskuser@example.com',
            password='StrongPass123'
        )

    @patch('apps.users.tasks.send_mail')
    @patch('apps.users.tasks.render_to_string')
    def test_send_welcome_email_success(self, mock_render_to_string, mock_send_mail):
        mock_render_to_string.return_value = '<p>Welcome!</p>'

        result = send_welcome_email(self.user.id)

        self.assertTrue(result)
        mock_render_to_string.assert_called_once()
        mock_send_mail.assert_called_once_with(
            subject='Welcome to Our Platform',
            message='',
            html_message='<p>Welcome!</p>',
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com'),
            recipient_list=[self.user.email],
            fail_silently=False,
        )

    @patch('apps.users.tasks.send_mail')
    def test_send_welcome_email_user_not_found(self, mock_send_mail):
        result = send_welcome_email(999999)

        self.assertFalse(result)
        mock_send_mail.assert_not_called()

    @patch('apps.users.tasks.send_mail')
    @patch('apps.users.tasks.render_to_string')
    def test_send_welcome_email_template_render_failure(self, mock_render_to_string, mock_send_mail):
        mock_render_to_string.side_effect = Exception('Template error')

        result = send_welcome_email(self.user.id)

        self.assertFalse(result)
        mock_send_mail.assert_not_called()

    def test_send_password_reset_email_success(self):
        result = send_password_reset_email(self.user.id, 'reset-token')

        self.assertTrue(result)

    def test_send_password_reset_email_user_not_found(self):
        result = send_password_reset_email(999999, 'reset-token')

        self.assertFalse(result)
