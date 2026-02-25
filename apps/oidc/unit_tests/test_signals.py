from django.test import TestCase
from unittest.mock import patch, MagicMock
from django.db.models.signals import post_save
from oauth2_provider.models import AccessToken
import apps.oidc.signals  # noqa: F401 (ensures signal is registered)

class OIDCSignalsTests(TestCase):
    @patch('apps.oidc.signals.logger')
    def test_log_token_creation_signal(self, mock_logger):
        # Create a fake AccessToken instance
        fake_token = MagicMock()
        fake_token.user_id = 42
        fake_token.application.client_id = 'client123'
        # Send the post_save signal
        post_save.send(sender=AccessToken, instance=fake_token, created=True)
        # Check logger.info was called with expected message
        mock_logger.info.assert_called_with(
            'Access token created for user 42 via client client123'
        )

    @patch('apps.oidc.signals.logger')
    def test_log_token_creation_signal_not_created(self, mock_logger):
        fake_token = MagicMock()
        fake_token.user_id = 42
        fake_token.application.client_id = 'client123'
        # created=False should not log
        post_save.send(sender=AccessToken, instance=fake_token, created=False)
        mock_logger.info.assert_not_called()
