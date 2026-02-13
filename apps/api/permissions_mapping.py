"""
OAuth2/OIDC Scope & Role to Django Permissions Mapping.

This module provides utilities to map OAuth2/OIDC claims (scopes, roles) to
Django Groups and Permissions, enabling fine-grained access control based on
token claims.

Features:
- Map OIDC roles/scope claims to Django groups
- Auto-provision groups and permissions
- Support custom scope-to-permission mappings
- Sync user group membership from token claims
- Django REST Framework permission classes based on scopes

Usage:
    from apps.api.permissions_mapping import map_token_claims_to_groups, ScopePermission
    
    # In authentication class:
    claims = token.claims  # from JWT or introspection
    user = authenticate_user(claims)
    map_token_claims_to_groups(user, claims)
    
    # In views:
    class MyView(APIView):
        permission_classes = [ScopePermission]
        required_scopes = ['api:read', 'api:write']
        
    # Or use built-in scope decorators:
    @scope_required('api:read', 'api:admin')
    def my_view(request):
        ...
"""

import logging
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from rest_framework import permissions
from rest_framework.decorators import permission_classes
from rest_framework.exceptions import PermissionDenied
from django.conf import settings

logger = logging.getLogger(__name__)


class ScopePermissionMapping:
    """
    Manages mapping between OAuth2 scopes/roles and Django permissions.
    
    Configuration in settings.py:
    
    SCOPE_TO_PERMISSION_MAP = {
        'api:read': ['view_user', 'view_order'],
        'api:write': ['add_user', 'change_user', 'add_order', 'change_order'],
        'admin': ['delete_user', 'delete_order'],
    }
    
    ROLE_TO_GROUP_MAP = {
        'admin': 'Administrators',
        'editor': 'Content Editors',
        'viewer': 'Viewers',
    }
    """
    
    def __init__(self):
        self.scope_to_permission = getattr(
            settings,
            'SCOPE_TO_PERMISSION_MAP',
            self._default_scope_mapping()
        )
        self.role_to_group = getattr(
            settings,
            'ROLE_TO_GROUP_MAP',
            self._default_role_mapping()
        )
    
    @staticmethod
    def _default_scope_mapping():
        """Default scope to permission mapping."""
        return {
            'api:read': [
                'view_user',
                'view_userprofile',
            ],
            'api:write': [
                'add_user',
                'change_user',
                'add_userprofile',
                'change_userprofile',
            ],
            'admin': [
                'delete_user',
                'delete_userprofile',
            ],
        }
    
    @staticmethod
    def _default_role_mapping():
        """Default role to group mapping."""
        return {
            'admin': 'Administrators',
            'editor': 'Editors',
            'viewer': 'Viewers',
        }
    
    def get_permissions_for_scope(self, scope):
        """
        Get Django permission codenames for a scope.
        
        Args:
            scope (str): OAuth2 scope (e.g., 'api:read')
            
        Returns:
            list: Permission codenames
        """
        return self.scope_to_permission.get(scope, [])
    
    def get_group_for_role(self, role):
        """
        Get Django group name for a role.
        
        Args:
            role (str): OIDC role claim value
            
        Returns:
            str: Django group name
        """
        return self.role_to_group.get(role, None)
    
    def get_all_permissions_for_scopes(self, scopes):
        """
        Get all Django permissions for a list of scopes.
        
        Args:
            scopes (list): List of scope strings
            
        Returns:
            set: Permission codenames
        """
        permissions = set()
        for scope in scopes:
            permissions.update(self.get_permissions_for_scope(scope))
        return permissions


def map_token_claims_to_groups(user, claims, sync=True):
    """
    Sync user's Django group membership from token claims.
    
    Extracts 'roles' claim (list of roles) and maps to Django groups.
    Optionally removes user from groups not in token.
    
    Args:
        user: Django User instance
        claims (dict): Token claims dictionary
        sync (bool): If True, remove user from groups not in token
        
    Returns:
        tuple: (added_groups, removed_groups) lists of group names
    """
    mapping = ScopePermissionMapping()
    
    # Extract roles from claims
    # Common claim names: 'roles', 'role', 'realm_access.roles', etc.
    token_roles = set()
    
    if 'roles' in claims:
        token_roles = set(claims['roles']) if isinstance(claims['roles'], list) else {claims['roles']}
    elif 'role' in claims:
        token_roles = {claims['role']}
    elif 'realm_access' in claims and 'roles' in claims['realm_access']:
        token_roles = set(claims['realm_access']['roles'])
    
    # Map roles to groups
    target_groups = set()
    for role in token_roles:
        group_name = mapping.get_group_for_role(role)
        if group_name:
            target_groups.add(group_name)
    
    # Get or create groups
    groups_to_add = []
    for group_name in target_groups:
        group, created = Group.objects.get_or_create(name=group_name)
        groups_to_add.append(group)
        if created:
            logger.info(f"Created new group: {group_name}")
    
    # Get current user groups
    current_groups = set(user.groups.values_list('name', flat=True))
    target_group_names = target_groups
    
    # Add groups
    added_groups = []
    for group in groups_to_add:
        if group.name not in current_groups:
            user.groups.add(group)
            added_groups.append(group.name)
            logger.debug(f"Added user {user.id} to group {group.name}")
    
    # Optionally remove groups
    removed_groups = []
    if sync:
        for group_name in current_groups:
            if group_name not in target_group_names:
                group = Group.objects.get(name=group_name)
                user.groups.remove(group)
                removed_groups.append(group_name)
                logger.debug(f"Removed user {user.id} from group {group_name}")
    
    return added_groups, removed_groups


def sync_permissions_from_token_scopes(user, scopes, sync=True):
    """
    Sync user's Django permissions from token scopes.
    
    Maps OAuth2 scopes to Django permissions and assigns them to user
    via group membership or direct permission assignment.
    
    Args:
        user: Django User instance
        scopes (list): List of scope strings (e.g., ['api:read', 'api:write'])
        sync (bool): If True, remove permissions not in scopes
        
    Returns:
        tuple: (added_permissions, removed_permissions) lists of permission names
    """
    mapping = ScopePermissionMapping()
    
    # Get target permissions from scopes
    target_perm_codenames = mapping.get_all_permissions_for_scopes(scopes)
    
    # Get or create permission objects
    added_perms = []
    try:
        for perm_codename in target_perm_codenames:
            try:
                # Permission codename format: 'app_label.permission_name' or just 'permission_name'
                if '.' in perm_codename:
                    app_label, perm = perm_codename.split('.')
                    permission = Permission.objects.get(
                        content_type__app_label=app_label,
                        codename=perm
                    )
                else:
                    permission = Permission.objects.get(codename=perm_codename)
                
                if not user.has_perm(f'{permission.content_type.app_label}.{permission.codename}'):
                    user.user_permissions.add(permission)
                    added_perms.append(permission.codename)
                    logger.debug(f"Added permission {permission.codename} to user {user.id}")
            except Permission.DoesNotExist:
                logger.warning(f"Permission not found: {perm_codename}")
    except Exception as e:
        logger.error(f"Error syncing permissions: {e}")
    
    # Optionally remove permissions
    removed_perms = []
    if sync:
        current_perms = set(user.user_permissions.values_list('codename', flat=True))
        for perm_codename in current_perms:
            if perm_codename not in target_perm_codenames:
                try:
                    permission = Permission.objects.get(codename=perm_codename)
                    user.user_permissions.remove(permission)
                    removed_perms.append(perm_codename)
                    logger.debug(f"Removed permission {perm_codename} from user {user.id}")
                except Permission.DoesNotExist:
                    pass
    
    return added_perms, removed_perms


class ScopePermission(permissions.BasePermission):
    """
    DRF permission class that checks token scopes.
    
    Usage in views:
        class MyView(APIView):
            permission_classes = [ScopePermission]
            required_scopes = ['api:read']  # Can be a string or list
            
    The request must have request.token_scopes (set by authentication class)
    """
    
    message = 'Insufficient scope for this resource.'
    
    def has_permission(self, request, view):
        """Check if request has required scopes."""
        required_scopes = getattr(view, 'required_scopes', None)
        
        if not required_scopes:
            return True
        
        # Normalize to list
        if isinstance(required_scopes, str):
            required_scopes = [required_scopes]
        
        # Get token scopes from request (set by authentication class)
        token_scopes = getattr(request, 'token_scopes', [])
        
        if not token_scopes:
            return False
        
        # Check if user has at least one of the required scopes
        # (use all() for AND logic, any() for OR logic)
        has_scope = any(scope in token_scopes for scope in required_scopes)
        
        if not has_scope:
            self.message = f'Required scopes: {required_scopes}. Your scopes: {token_scopes}'
        
        return has_scope


class RolePermission(permissions.BasePermission):
    """
    DRF permission class that checks user group membership.
    
    Usage in views:
        class AdminView(APIView):
            permission_classes = [RolePermission]
            required_roles = ['Administrators']
    """
    
    message = 'Insufficient role for this resource.'
    
    def has_permission(self, request, view):
        """Check if user is in required groups."""
        required_roles = getattr(view, 'required_roles', None)
        
        if not required_roles:
            return True
        
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Normalize to list
        if isinstance(required_roles, str):
            required_roles = [required_roles]
        
        # Get user's groups
        user_groups = set(request.user.groups.values_list('name', flat=True))
        
        # Check if user has at least one required role
        has_role = any(role in user_groups for role in required_roles)
        
        if not has_role:
            self.message = f'Required roles: {required_roles}. Your roles: {user_groups}'
        
        return has_role


def scope_required(*required_scopes):
    """
    Decorator to require specific OAuth2 scopes.
    
    Usage:
        @scope_required('api:read', 'api:write')
        def my_view(request):
            ...
    
    Args:
        *required_scopes: Variable number of required scope strings
    """
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            token_scopes = getattr(request, 'token_scopes', [])
            
            if not any(scope in token_scopes for scope in required_scopes):
                raise PermissionDenied(
                    f'Required scopes: {required_scopes}. Your scopes: {token_scopes}'
                )
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    
    return decorator


def role_required(*required_roles):
    """
    Decorator to require specific Django group membership.
    
    Usage:
        @role_required('Administrators')
        def my_view(request):
            ...
    
    Args:
        *required_roles: Variable number of required group names
    """
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if not request.user or not request.user.is_authenticated:
                raise PermissionDenied('Authentication required')
            
            user_groups = set(request.user.groups.values_list('name', flat=True))
            
            if not any(role in user_groups for role in required_roles):
                raise PermissionDenied(
                    f'Required roles: {required_roles}. Your roles: {user_groups}'
                )
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    
    return decorator
