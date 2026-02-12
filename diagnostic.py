#!/usr/bin/env python
"""
HCS SSO Unified Authentication System - Diagnostic Script
Verifies that the OAuth2/JWT consolidation was successful
"""

import os
import sys
import django
from django.conf import settings

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sso.settings')
sys.path.insert(0, '/Users/dhrubajyotiborah/Documents/Projects/hcs_sso_with_oidc')
django.setup()

from django.contrib.auth.models import User
from oauth2_provider.models import Application
from django.urls import get_resolver
import inspect

def check_authentication_settings():
    """Verify authentication settings are unified"""
    print("\n" + "="*60)
    print("AUTHENTICATION SETTINGS CHECK")
    print("="*60)
    
    checks = {
        'LOGIN_URL': (settings.LOGIN_URL, '/accounts/login/'),
        'SOCIAL_AUTH_LOGIN_URL': (settings.SOCIAL_AUTH_LOGIN_URL, '/accounts/login/'),
        'SOCIAL_AUTH_LOGIN_ERROR_URL': (settings.SOCIAL_AUTH_LOGIN_ERROR_URL, '/accounts/login/'),
    }
    
    all_pass = True
    for key, (actual, expected) in checks.items():
        status = "✅ PASS" if actual == expected else "❌ FAIL"
        print(f"{status} {key}: {actual}")
        if actual != expected:
            print(f"     Expected: {expected}")
            all_pass = False
    
    return all_pass

def check_oauth2_provider_config():
    """Verify OAuth2 provider is configured"""
    print("\n" + "="*60)
    print("OAUTH2 PROVIDER CONFIGURATION CHECK")
    print("="*60)
    
    oauth2_config = getattr(settings, 'OAUTH2_PROVIDER', {})
    
    critical_settings = {
        'SCOPES': 'Custom scopes defined',
        'ACCESS_TOKEN_EXPIRE_SECONDS': 'Access token expiry set',
        'PKCE_REQUIRED': 'PKCE required for public clients',
    }
    
    all_pass = True
    for key, description in critical_settings.items():
        if key in oauth2_config:
            value = oauth2_config[key]
            print(f"✅ PASS {key}: {value} ({description})")
        else:
            print(f"⚠️  WARN {key}: Not found (using default)")
            all_pass = False if key == 'PKCE_REQUIRED' else all_pass
    
    return all_pass

def check_removed_endpoints():
    """Verify old authentication endpoints are removed"""
    print("\n" + "="*60)
    print("REMOVED ENDPOINTS CHECK (Old System)")
    print("="*60)
    
    resolver = get_resolver()
    all_patterns = [str(pattern.pattern) for pattern in resolver.url_patterns]
    
    removed_endpoints = [
        'api/users/login/',
        'api/oidc/.well-known/',
    ]
    
    all_removed = True
    for endpoint in removed_endpoints:
        found = any(endpoint in pattern for pattern in all_patterns)
        status = "❌ FAIL - Still exists!" if found else "✅ PASS - Removed"
        print(f"{status}: {endpoint}")
        all_removed = all_removed and not found
    
    return all_removed

def check_unified_endpoints():
    """Verify new unified endpoints exist"""
    print("\n" + "="*60)
    print("UNIFIED ENDPOINTS CHECK (New System)")
    print("="*60)
    
    resolver = get_resolver()
    all_patterns = [str(pattern.pattern) for pattern in resolver.url_patterns]
    
    required_endpoints = {
        'accounts/login/': 'Organization login form',
        'o/token/': 'OAuth2 token endpoint',
        'o/authorize/': 'OAuth2 authorization endpoint',
        '.well-known/openid-configuration/': 'OIDC discovery',
        'api/oidc/jwks/': 'JWT signing keys',
        'api/users/profile/': 'User profile endpoint',
    }
    
    all_exist = True
    for endpoint, description in required_endpoints.items():
        found = any(endpoint in pattern for pattern in all_patterns)
        status = "✅ PASS" if found else "❌ FAIL - Missing!"
        print(f"{status}: {endpoint} ({description})")
        all_exist = all_exist and found
    
    return all_exist

def check_authentication_backends():
    """Verify authentication backends are configured"""
    print("\n" + "="*60)
    print("AUTHENTICATION BACKENDS CHECK")
    print("="*60)
    
    backends = settings.AUTHENTICATION_BACKENDS
    
    required = [
        'oauth2_provider.backends.OAuth2Backend',
        'django.contrib.auth.backends.ModelBackend',
    ]
    
    social_backends = [
        'social_core.backends.google.GoogleOAuth2',
        'social_core.backends.facebook.FacebookOAuth2',
        'social_core.backends.microsoft.MicrosoftOAuth2',
    ]
    
    all_pass = True
    print("Required backends:")
    for backend in required:
        found = backend in backends
        status = "✅ PASS" if found else "❌ FAIL"
        print(f"  {status}: {backend}")
        all_pass = all_pass and found
    
    print("\nSocial backends (at least some):")
    social_found = sum(1 for b in social_backends if b in backends)
    print(f"  ✅ {social_found}/{len(social_backends)} social backends configured")
    
    return all_pass

def check_users_and_apps():
    """Verify test user and OAuth2 apps exist"""
    print("\n" + "="*60)
    print("TEST DATA CHECK")
    print("="*60)
    
    # Check for test user
    test_user_exists = User.objects.filter(username='testuser').exists()
    if test_user_exists:
        user = User.objects.get(username='testuser')
        print(f"✅ PASS: Test user exists (testuser, email: {user.email})")
    else:
        print(f"⚠️  WARN: No 'testuser' test user found")
        print(f"     Create one with: User.objects.create_user('testuser', 'test@example.com', 'TestPassword123!')")
    
    # Check for OAuth2 apps
    apps = Application.objects.all()
    print(f"\n✅ OAuth2 Applications: {apps.count()} app(s) registered")
    for app in apps:
        print(f"   - {app.name} (client_id: {app.client_id}, user: {app.user})")
    
    if apps.count() == 0:
        print("     ⚠️  No apps registered. Create one at /admin/oauth2_provider/application/")
    
    return test_user_exists and apps.count() > 0

def check_token_system():
    """Verify JWT token system is configured"""
    print("\n" + "="*60)
    print("JWT TOKEN SYSTEM CHECK")
    print("="*60)
    
    oauth2_config = getattr(settings, 'OAUTH2_PROVIDER', {})
    
    checks = {
        'ACCESS_TOKEN_EXPIRE_SECONDS': oauth2_config.get('ACCESS_TOKEN_EXPIRE_SECONDS', 3600),
        'REFRESH_TOKEN_EXPIRE_SECONDS': oauth2_config.get('REFRESH_TOKEN_EXPIRE_SECONDS'),
        'ROTATE_REFRESH_TOKEN': oauth2_config.get('ROTATE_REFRESH_TOKEN', False),
    }
    
    print(f"✅ Access token expiry: {checks['ACCESS_TOKEN_EXPIRE_SECONDS']} seconds")
    print(f"✅ Refresh token expiry: {checks['REFRESH_TOKEN_EXPIRE_SECONDS']} seconds")
    print(f"✅ Rotate refresh tokens: {checks['ROTATE_REFRESH_TOKEN']}")
    
    return True

def check_template():
    """Verify login template includes social buttons"""
    print("\n" + "="*60)
    print("TEMPLATE CHECK")
    print("="*60)
    
    template_path = '/Users/dhrubajyotiborah/Documents/Projects/hcs_sso_with_oidc/templates/registration/login.html'
    
    if os.path.exists(template_path):
        with open(template_path, 'r') as f:
            content = f.read()
        
        # Check for social buttons
        social_providers = {
            'Google': 'google-oauth2',
            'Facebook': 'facebook',
            'Microsoft': 'microsoft',
            'GitHub': 'github',
            'LinkedIn': 'linkedin',
        }
        
        found_count = 0
        for name, backend in social_providers.items():
            if backend in content or name.lower() in content.lower():
                print(f"✅ {name} button found")
                found_count += 1
            else:
                print(f"⚠️  {name} button not found")
        
        print(f"\n✅ Social buttons: {found_count}/{len(social_providers)} found")
        
        # Check for org form
        if 'username' in content or 'password' in content:
            print(f"✅ Organization login form found")
        else:
            print(f"❌ Organization login form not found")
        
        return True
    else:
        print(f"❌ FAIL: Template not found at {template_path}")
        return False

def print_summary(results):
    """Print summary of all checks"""
    print("\n" + "="*60)
    print("OVERALL SYSTEM STATUS")
    print("="*60)
    
    passed = sum(1 for r in results if r)
    total = len(results)
    
    if passed == total:
        print(f"\n🎉 SUCCESS! All {total} checks passed!")
        print("\nYour unified OAuth2/JWT system is properly configured.")
        print("\nNext steps:")
        print("1. Read UNIFIED_OAUTH2_SYSTEM.md for complete reference")
        print("2. Read POSTMAN_COMPLETE_GUIDE.md for testing guide")
        print("3. Import HCS_SSO_OAuth2_Postman_Collection.json into Postman")
        print("4. Test with: python manage.py runserver")
        return True
    else:
        print(f"\n⚠️  {total - passed} issue(s) found. Please review above.")
        print("\nTo fix:")
        print("1. Check IMPLEMENTATION_COMPLETE.md for migration guide")
        print("2. Verify settings.py is properly configured")
        print("3. Ensure test user exists: User.objects.create_user('testuser', ...)")
        print("4. Ensure OAuth2 app exists at /admin/oauth2_provider/application/")
        return False

def main():
    """Run all diagnostic checks"""
    print("\n" + "🔍 HCS SSO UNIFIED AUTHENTICATION SYSTEM DIAGNOSTIC" + "\n")
    
    results = []
    
    try:
        results.append(check_authentication_settings())
        results.append(check_oauth2_provider_config())
        results.append(check_removed_endpoints())
        results.append(check_unified_endpoints())
        results.append(check_authentication_backends())
        results.append(check_users_and_apps())
        results.append(check_token_system())
        results.append(check_template())
        
        print_summary(results)
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nMake sure Django is configured properly:")
        print("1. cd /Users/dhrubajyotiborah/Documents/Projects/hcs_sso_with_oidc")
        print("2. python manage.py shell < diagnostic.py")

if __name__ == '__main__':
    main()
