from django.test import SimpleTestCase
from django.urls import reverse, resolve
from apps.oidc.urls import app_name
from apps.oidc.views.discovery import JWKSDocumentView, OIDCProviderInfoView
from apps.oidc.views.token import OIDCUserInfoView, TokenIntrospectionView, TokenRevocationView, SessionManagementView
from apps.oidc.views.client import ClientRegistrationView

class OIDCURLPatternsTests(SimpleTestCase):
    def test_jwks_url(self):
        url = reverse(f'{app_name}:oidc-jwks')
        resolver = resolve(url)
        self.assertEqual(resolver.func.view_class, JWKSDocumentView)

    def test_provider_info_url(self):
        url = reverse(f'{app_name}:oidc-provider-info')
        resolver = resolve(url)
        self.assertEqual(resolver.func.view_class, OIDCProviderInfoView)

    def test_userinfo_url(self):
        url = reverse(f'{app_name}:oidc-userinfo')
        resolver = resolve(url)
        self.assertEqual(resolver.func.view_class, OIDCUserInfoView)

    def test_introspect_url(self):
        url = reverse(f'{app_name}:oidc-introspect')
        resolver = resolve(url)
        self.assertEqual(resolver.func.view_class, TokenIntrospectionView)

    def test_revoke_url(self):
        url = reverse(f'{app_name}:oidc-revoke')
        resolver = resolve(url)
        self.assertEqual(resolver.func.view_class, TokenRevocationView)

    def test_sessions_url(self):
        url = reverse(f'{app_name}:oidc-sessions')
        resolver = resolve(url)
        self.assertEqual(resolver.func.view_class, SessionManagementView)

    def test_session_detail_url(self):
        url = reverse(f'{app_name}:oidc-session-detail', kwargs={'session_id': 42})
        resolver = resolve(url)
        self.assertEqual(resolver.func.view_class, SessionManagementView)

    def test_register_url(self):
        url = reverse(f'{app_name}:oidc-register')
        resolver = resolve(url)
        self.assertEqual(resolver.func.view_class, ClientRegistrationView)
