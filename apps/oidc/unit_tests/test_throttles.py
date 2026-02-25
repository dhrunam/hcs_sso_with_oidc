import json

from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework.request import Request
from rest_framework.parsers import JSONParser
from django.contrib.auth import get_user_model
from apps.oidc.throttles import JWKSThrottle, IntrospectionThrottle, RegistrationThrottle

User = get_user_model()

class ThrottleTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(username='testuser', password='testpass')

    def test_jwks_throttle_authenticated(self):
        req = self.factory.get('/api/oidc/jwks/')
        force_authenticate(req, user=self.user)
        request = Request(req)
        throttle = JWKSThrottle()
        key = throttle.get_cache_key(request, view=None)
        self.assertIn('jwks', key)
        self.assertIn(str(self.user.pk), key)

    def test_jwks_throttle_anon(self):
        req = self.factory.get('/api/oidc/jwks/')
        request = Request(req)
        throttle = JWKSThrottle()
        key = throttle.get_cache_key(request, view=None)
        self.assertIn('jwks', key)
        self.assertIsInstance(key, str)

    def test_introspection_throttle_with_client_id(self):
        req = self.factory.post(
            '/api/oidc/introspect/', {'client_id': 'client123'}, format='json'
        )
        force_authenticate(req, user=self.user)
        request = Request(req, parsers=[JSONParser()])
        throttle = IntrospectionThrottle()
        key = throttle.get_cache_key(request, view=None)
        self.assertIn('introspection', key)
        self.assertIn('client123', key)

    def test_introspection_throttle_authenticated(self):
        req = self.factory.post(
            '/api/oidc/introspect/', {}, format='json'
        )
        force_authenticate(req, user=self.user)
        request = Request(req, parsers=[JSONParser()])
        throttle = IntrospectionThrottle()
        key = throttle.get_cache_key(request, view=None)
        self.assertIn('introspection', key)
        self.assertIn(str(self.user.pk), key)

    def test_introspection_throttle_anon(self):
        req = self.factory.post(
            '/api/oidc/introspect/', {}, format='json'
        )
        request = Request(req, parsers=[JSONParser()])
        throttle = IntrospectionThrottle()
        key = throttle.get_cache_key(request, view=None)
        self.assertIn('introspection', key)
        self.assertIsInstance(key, str)

    def test_registration_throttle_authenticated(self):
        req = self.factory.post('/api/oidc/register/', {}, format='json')
        force_authenticate(req, user=self.user)
        request = Request(req)
        throttle = RegistrationThrottle()
        key = throttle.get_cache_key(request, view=None)
        self.assertIn('registration', key)
        self.assertIn(str(self.user.pk), key)

    def test_registration_throttle_anon(self):
        req = self.factory.post('/api/oidc/register/', {}, format='json')
        request = Request(req)
        throttle = RegistrationThrottle()
        key = throttle.get_cache_key(request, view=None)
        self.assertIn('registration', key)
        self.assertIsInstance(key, str)
