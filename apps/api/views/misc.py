from datetime import datetime

from django.conf import settings
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.throttling import AnonRateThrottle
from rest_framework.decorators import api_view, permission_classes, throttle_classes


@api_view(['GET'])
@permission_classes([AllowAny])
@throttle_classes([AnonRateThrottle])
def robots_txt(request):
    content = """User-agent: *
Disallow: /admin/
Disallow: /api/health/
Disallow: /api/metrics/
Disallow: /api/system/

# Allow API documentation
Allow: /api/docs/
Allow: /api/redoc/

# Allow OIDC discovery
Allow: /.well-known/

Sitemap: https://yoursite.com/sitemap.xml
"""
    return Response(content, content_type='text/plain')


@api_view(['GET'])
@permission_classes([AllowAny])
def security_txt(request):
    content = f"""Contact: mailto:{getattr(settings, 'SECURITY_CONTACT_EMAIL', 'security@example.com')}
Expires: {datetime.now().replace(year=datetime.now().year + 1).strftime('%Y-%m-%dT%H:%M:%S.%fZ')}
Preferred-Languages: en
Acknowledgments: https://yoursite.com/security/acknowledgements
Policy: https://yoursite.com/security/policy
Signature: https://yoursite.com/.well-known/security.txt.sig
"""

    response = Response(content, content_type='text/plain')
    response['Content-Disposition'] = 'inline'
    return response
