# apps/users/serializers.py
"""
Serializers for user management, profiles, and authentication.
"""

import re
import logging
from typing import Dict, Any
from rest_framework import serializers
from django.contrib.auth.models import User, Group, Permission
from django.contrib.auth.password_validation import validate_password
from django.core.validators import validate_email as django_validate_email
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from django.db import transaction
from django.conf import settings

from apps.core.models import UserProfile, Department, Organization
from apps.social.models import SocialConnection
from apps.social.serializers import SocialConnectionSerializer

logger = logging.getLogger(__name__)

# Email validation regex
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

# Phone number validation regex (basic international format)
PHONE_REGEX = r'^\+?1?\d{9,15}$'


class OrganizationSerializer(serializers.ModelSerializer):
    """Serializer for Organization model"""
    
    class Meta:
        model = Organization
        fields = [
            'id', 'name', 'domain', 'logo', 'is_active',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate_domain(self, value: str) -> str:
        """Validate domain format"""
        if value:
            value = value.lower().strip()
            # Basic domain validation
            if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
                raise serializers.ValidationError("Invalid domain format")
        return value


class DepartmentSerializer(serializers.ModelSerializer):
    """Serializer for Department model"""
    
    organization_name = serializers.CharField(
        source='organization.name', 
        read_only=True
    )
    organization_domain = serializers.CharField(
        source='organization.domain', 
        read_only=True
    )
    
    class Meta:
        model = Department
        fields = [
            'id', 'name', 'code', 'description',
            'organization', 'organization_name', 'organization_domain',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate_code(self, value: str) -> str:
        """Validate department code"""
        if value:
            value = value.upper().strip()
            if not re.match(r'^[A-Z0-9_-]+$', value):
                raise serializers.ValidationError(
                    "Department code can only contain uppercase letters, numbers, hyphens, and underscores"
                )
        return value
    
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Validate department data"""
        # Ensure unique name within organization
        if 'name' in attrs and 'organization' in attrs:
            department = Department.objects.filter(
                name=attrs['name'],
                organization=attrs['organization']
            ).exclude(id=self.instance.id if self.instance else None).first()
            
            if department:
                raise serializers.ValidationError({
                    'name': 'A department with this name already exists in this organization'
                })
        
        return attrs


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for UserProfile model"""
    
    department_details = DepartmentSerializer(
        source='department', 
        read_only=True
    )
    organization = serializers.SerializerMethodField(read_only=True)
    social_connections = serializers.SerializerMethodField(read_only=True)
    mfa_enabled = serializers.BooleanField(read_only=True)
    email_verified = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = [
            # Basic info
            'id', 'employee_id', 'department', 'department_details',
            'phone_number', 'job_title', 'avatar',
            
            # Identity provider info
            'external_id', 'identity_provider', 'email_verified',
            
            # Preferences
            'preferred_language', 'timezone', 'mfa_enabled',
            
            # Social connections
            'social_connections',
            
            # Organization (computed)
            'organization',
            
            # Timestamps
            'created_at', 'updated_at', 'last_login_at'
        ]
        read_only_fields = [
            'id', 'external_id', 'identity_provider', 'email_verified',
            'mfa_enabled', 'created_at', 'updated_at', 'last_login_at',
            'social_connections', 'organization'
        ]
    
    def get_organization(self, obj) -> Dict[str, Any]:
        """Get organization info from department"""
        if obj.department and obj.department.organization:
            return {
                'id': obj.department.organization.id,
                'name': obj.department.organization.name,
                'domain': obj.department.organization.domain,
            }
        return None
    
    def get_social_connections(self, obj) -> list:
        """Get user's active social connections"""
        request = self.context.get('request')
        if request and request.user == obj.user:
            connections = SocialConnection.objects.filter(
                user=obj.user,
                is_active=True
            )
            return SocialConnectionSerializer(connections, many=True).data
        return []
    
    def validate_phone_number(self, value: str) -> str:
        """Validate phone number format"""
        if value and not re.match(PHONE_REGEX, value.replace(' ', '')):
            raise serializers.ValidationError(
                "Phone number must be in international format (e.g., +1234567890)"
            )
        return value
    
    def validate_employee_id(self, value: str) -> str:
        """Validate employee ID"""
        if value and len(value) > 50:
            raise serializers.ValidationError(
                "Employee ID cannot exceed 50 characters"
            )
        return value.upper() if value else value


class UserMinimalSerializer(serializers.ModelSerializer):
    """Minimal user serializer for list views and references"""
    
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'full_name']
        read_only_fields = fields
    
    def get_full_name(self, obj) -> str:
        return obj.get_full_name() or obj.username


class UserSerializer(serializers.ModelSerializer):
    """Complete user serializer for detailed views"""
    
    profile = UserProfileSerializer(read_only=True)
    full_name = serializers.SerializerMethodField()
    groups = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()
    is_oauth_user = serializers.SerializerMethodField()
    has_password = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            # Basic info
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            
            # Status
            'is_active', 'is_staff', 'is_superuser',
            
            # Auth info
            'has_password', 'is_oauth_user',
            
            # Permissions
            'groups', 'permissions',
            
            # Profile
            'profile',
            
            # Timestamps
            'date_joined', 'last_login'
        ]
        read_only_fields = [
            'id', 'is_staff', 'is_superuser', 'date_joined', 'last_login',
            'groups', 'permissions', 'is_oauth_user', 'has_password'
        ]
    
    def get_full_name(self, obj) -> str:
        return obj.get_full_name() or obj.username
    
    def get_groups(self, obj) -> list:
        """Get user's groups"""
        return list(obj.groups.values_list('name', flat=True))
    
    def get_permissions(self, obj) -> list:
        """Get user's permissions"""
        return list(obj.get_all_permissions())
    
    def get_is_oauth_user(self, obj) -> bool:
        """Check if user has social connections"""
        return SocialConnection.objects.filter(user=obj, is_active=True).exists()
    
    def get_has_password(self, obj) -> bool:
        """Check if user has a password set"""
        return obj.has_usable_password()


class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'},
        min_length=8,
        max_length=128
    )
    password2 = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    profile = UserProfileSerializer(required=False)
    
    class Meta:
        model = User
        fields = [
            'username', 'email', 'first_name', 'last_name',
            'password', 'password2', 'profile'
        ]
    
    def validate_username(self, value: str) -> str:
        """Validate username"""
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("A user with this username already exists.")
        
        # Username validation
        if not re.match(r'^[a-zA-Z0-9._-]+$', value):
            raise serializers.ValidationError(
                "Username can only contain letters, numbers, dots, hyphens, and underscores."
            )
        
        if len(value) < 3:
            raise serializers.ValidationError("Username must be at least 3 characters long.")
        
        return value.lower()
    
    def validate_email(self, value: str) -> str:
        """Validate email"""
        if not value:
            raise serializers.ValidationError("Email is required")
        
        # Django email validation
        try:
            django_validate_email(value)
        except DjangoValidationError:
            raise serializers.ValidationError("Enter a valid email address.")
        
        # Check uniqueness
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        
        return value.lower()
    
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Validate registration data"""
        # Password confirmation
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({
                'password': 'Passwords do not match.'
            })
        
        # Profile validation
        profile_data = attrs.get('profile', {})
        if 'employee_id' in profile_data and profile_data['employee_id']:
            # Check employee ID uniqueness
            if UserProfile.objects.filter(
                employee_id=profile_data['employee_id']
            ).exists():
                raise serializers.ValidationError({
                    'profile': {'employee_id': 'This employee ID is already in use.'}
                })
        
        return attrs
    
    @transaction.atomic
    def create(self, validated_data: Dict[str, Any]) -> User:
        """Create a new user with profile"""
        profile_data = validated_data.pop('profile', {})
        validated_data.pop('password2', None)
        
        # Create user (signal handler will auto-create UserProfile)
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            is_active=True  # Auto-activate, or make configurable
        )
        
        # Update profile with additional data if provided
        # (signal handler already created the UserProfile instance)
        if profile_data:
            profile = user.userprofile
            for key, value in profile_data.items():
                setattr(profile, key, value)
            profile.save()
        
        # Assign default group if configured
        default_group = getattr(settings, 'DEFAULT_USER_GROUP', None)
        if default_group:
            try:
                group = Group.objects.get(name=default_group)
                user.groups.add(group)
            except Group.DoesNotExist:
                logger.warning(f"Default group '{default_group}' not found")
        
        logger.info(f"User created: {user.username} ({user.email})")
        
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user information"""
    
    profile = UserProfileSerializer()
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'profile']
    
    def validate_email(self, value: str) -> str:
        """Validate email on update"""
        request = self.context.get('request')
        if not request or not request.user:
            return value
        
        # Check if email is being changed
        if request.user.email != value:
            # Check uniqueness
            if User.objects.filter(email__iexact=value).exclude(id=request.user.id).exists():
                raise serializers.ValidationError("A user with this email already exists.")
            
            # Email verification could be triggered here
            logger.info(f"User {request.user.id} changed email from {request.user.email} to {value}")
        
        return value.lower()
    
    @transaction.atomic
    def update(self, instance: User, validated_data: Dict[str, Any]) -> User:
        """Update user and profile"""
        profile_data = validated_data.pop('profile', {})
        
        # Update user fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        
        # Update profile
        if profile_data:
            profile = instance.profile
            for attr, value in profile_data.items():
                # Handle department assignment
                if attr == 'department' and value:
                    # Ensure department exists and user can be assigned
                    try:
                        department = Department.objects.get(id=value.id)
                        setattr(profile, attr, department)
                    except Department.DoesNotExist:
                        raise serializers.ValidationError({
                            'profile': {'department': 'Invalid department'}
                        })
                else:
                    setattr(profile, attr, value)
            
            profile.save()
        
        logger.info(f"User updated: {instance.username}")
        
        return instance


class AdminUserUpdateSerializer(UserUpdateSerializer):
    """Admin serializer for updating user information"""
    
    is_active = serializers.BooleanField(required=False)
    groups = serializers.PrimaryKeyRelatedField(
        queryset=Group.objects.all(),
        many=True,
        required=False
    )
    
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'email', 'profile',
            'is_active', 'groups'
        ]
    
    @transaction.atomic
    def update(self, instance: User, validated_data: Dict[str, Any]) -> User:
        """Update user with admin privileges"""
        groups = validated_data.pop('groups', None)
        
        # Update basic fields
        instance = super().update(instance, validated_data)
        
        # Update groups if provided
        if groups is not None:
            instance.groups.set(groups)
        
        return instance


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for changing password"""
    
    old_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'},
        min_length=8,
        max_length=128
    )
    confirm_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    
    def validate_old_password(self, value: str) -> str:
        """Validate old password"""
        request = self.context.get('request')
        if not request or not request.user:
            raise serializers.ValidationError("Authentication required")
        
        if not request.user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect")
        
        return value
    
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Validate password change"""
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({
                'new_password': 'Passwords do not match'
            })
        
        # Prevent reusing old password
        if attrs['old_password'] == attrs['new_password']:
            raise serializers.ValidationError({
                'new_password': 'New password must be different from current password'
            })
        
        return attrs
    
    def save(self, **kwargs):
        """Change user password"""
        request = self.context.get('request')
        if not request or not request.user:
            raise serializers.ValidationError("Authentication required")
        
        user = request.user
        user.set_password(self.validated_data['new_password'])
        user.save()
        
        logger.info(f"Password changed for user: {user.username}")
        
        return user


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for requesting password reset"""
    
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value: str) -> str:
        """Validate email exists"""
        if not User.objects.filter(email__iexact=value, is_active=True).exists():
            # Don't reveal if user exists (security best practice)
            raise serializers.ValidationError(
                "If an account exists with this email, you will receive a password reset link."
            )
        return value.lower()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for confirming password reset"""
    
    token = serializers.CharField(required=True)
    uid = serializers.CharField(required=True)
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'},
        min_length=8,
        max_length=128
    )
    confirm_password = serializers.CharField(
        required=True,
        style={'input_type': 'password'}
    )
    
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Validate password reset"""
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({
                'new_password': 'Passwords do not match'
            })
        return attrs


class UserBulkUpdateSerializer(serializers.Serializer):
    """Serializer for bulk user updates (admin only)"""
    
    user_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=True
    )
    is_active = serializers.BooleanField(required=False)
    department_id = serializers.IntegerField(required=False)
    
    def validate_user_ids(self, value: list) -> list:
        """Validate user IDs exist"""
        users = User.objects.filter(id__in=value)
        if len(users) != len(value):
            raise serializers.ValidationError("One or more user IDs are invalid")
        return value
    
    def validate_department_id(self, value: int) -> int:
        """Validate department exists"""
        if value and not Department.objects.filter(id=value).exists():
            raise serializers.ValidationError("Department does not exist")
        return value


class UserStatsSerializer(serializers.Serializer):
    """Serializer for user statistics"""
    
    total_users = serializers.IntegerField()
    active_users = serializers.IntegerField()
    inactive_users = serializers.IntegerField()
    social_users = serializers.IntegerField()
    staff_users = serializers.IntegerField()
    superusers = serializers.IntegerField()
    
    # By organization
    users_by_organization = serializers.DictField(
        child=serializers.IntegerField()
    )
    
    # By department
    users_by_department = serializers.DictField(
        child=serializers.IntegerField()
    )
    
    # Growth
    new_users_last_30_days = serializers.IntegerField()
    new_users_last_7_days = serializers.IntegerField()


# Utility functions
def get_user_stats() -> Dict[str, Any]:
    """Get user statistics for admin dashboard"""
    total_users = User.objects.count()
    active_users = User.objects.filter(is_active=True).count()
    
    # Social users
    social_user_ids = SocialConnection.objects.filter(
        is_active=True
    ).values_list('user_id', flat=True).distinct()
    social_users = User.objects.filter(id__in=social_user_ids).count()
    
    # Staff and superusers
    staff_users = User.objects.filter(is_staff=True).count()
    superusers = User.objects.filter(is_superuser=True).count()
    
    # Growth
    thirty_days_ago = timezone.now() - timezone.timedelta(days=30)
    seven_days_ago = timezone.now() - timezone.timedelta(days=7)
    
    new_users_last_30_days = User.objects.filter(
        date_joined__gte=thirty_days_ago
    ).count()
    
    new_users_last_7_days = User.objects.filter(
        date_joined__gte=seven_days_ago
    ).count()
    
    # Organization stats
    users_by_organization = {}
    for org in Organization.objects.all():
        count = UserProfile.objects.filter(
            department__organization=org
        ).count()
        if count > 0:
            users_by_organization[org.name] = count
    
    # Department stats
    users_by_department = {}
    for dept in Department.objects.all():
        count = UserProfile.objects.filter(department=dept).count()
        if count > 0:
            users_by_department[dept.name] = count
    
    return {
        'total_users': total_users,
        'active_users': active_users,
        'inactive_users': total_users - active_users,
        'social_users': social_users,
        'staff_users': staff_users,
        'superusers': superusers,
        'users_by_organization': users_by_organization,
        'users_by_department': users_by_department,
        'new_users_last_30_days': new_users_last_30_days,
        'new_users_last_7_days': new_users_last_7_days,
    }