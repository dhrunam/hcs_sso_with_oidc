from apps.oidc.serializers import ClientRegistrationSerializer

from .health import HealthCheckView
from .system import SystemInfoView
from .metrics import MetricsView
from .clients import ClientRegistrationView, ClientManagementView
from .root import APIRootView
from .misc import robots_txt, security_txt
from .bff import (
    BFFLoginSerializer,
    BFFTokenRefreshSerializer,
    BFFLogoutSerializer,
    exchange_authorization_code_for_tokens,
    refresh_access_token,
    set_refresh_token_cookie,
    clear_refresh_token_cookie,
    BFFLoginView,
    BFFTokenRefreshView,
    BFFLogoutView,
    BFFAuthViewSet,
)

__all__ = [
    'HealthCheckView',
    'SystemInfoView',
    'MetricsView',
    'ClientRegistrationView',
    'ClientManagementView',
    'APIRootView',
    'robots_txt',
    'security_txt',
    'ClientRegistrationSerializer',
    'BFFLoginSerializer',
    'BFFTokenRefreshSerializer',
    'BFFLogoutSerializer',
    'exchange_authorization_code_for_tokens',
    'refresh_access_token',
    'set_refresh_token_cookie',
    'clear_refresh_token_cookie',
    'BFFLoginView',
    'BFFTokenRefreshView',
    'BFFLogoutView',
    'BFFAuthViewSet',
]
