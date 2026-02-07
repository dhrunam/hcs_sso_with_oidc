# apps/core/models.py

from django.db import models
from django.contrib.auth.models import User
from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

class TimeStampedModel(models.Model):
    """Abstract base model for tracking creation and update timestamps"""
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Created At'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Updated At'))
    
    class Meta:
        abstract = True

class Organization(TimeStampedModel):
    """Organization model for multi-tenancy support"""
    name = models.CharField(max_length=255, verbose_name=_('Name'))
    domain = models.CharField(
        max_length=255, 
        unique=True, 
        verbose_name=_('Domain'),
        help_text=_('Primary domain associated with this organization')
    )
    logo = models.FileField(
        upload_to='organizations/',
        null=True,
        blank=True,
        verbose_name=_('Logo'),
        validators=[
            FileExtensionValidator(
                allowed_extensions=['jpg', 'jpeg', 'png', 'gif', 'svg'],
                message=_('Only image files (JPG, PNG, GIF, SVG) are allowed')
            )
        ],
        help_text=_('Organization logo. Recommended size: 200x200 pixels')
    )
    is_active = models.BooleanField(default=True, verbose_name=_('Is Active'))
    
    class Meta:
        verbose_name = _('Organization')
        verbose_name_plural = _('Organizations')
        indexes = [
            models.Index(fields=['domain']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return self.name
    
    def clean(self):
        """Validate organization data"""
        super().clean()
        # Ensure domain is lowercase and stripped
        if self.domain:
            self.domain = self.domain.lower().strip()
        
        # Validate logo file size (optional, can be added in form/serializer)
        # if self.logo and self.logo.size > 5 * 1024 * 1024:  # 5MB
        #     raise ValidationError({'logo': _('Logo file size must be less than 5MB')})

class Department(TimeStampedModel):
    """Department model within an organization"""
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='departments',
        verbose_name=_('Organization')
    )
    name = models.CharField(max_length=255, verbose_name=_('Name'))
    code = models.CharField(
        max_length=50,
        unique=True,
        verbose_name=_('Department Code'),
        help_text=_('Unique identifier for the department')
    )
    description = models.TextField(blank=True, verbose_name=_('Description'))
    
    class Meta:
        verbose_name = _('Department')
        verbose_name_plural = _('Departments')
        ordering = ['organization', 'name']
        indexes = [
            models.Index(fields=['code']),
            models.Index(fields=['organization']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['organization', 'name'],
                name='unique_department_name_per_org'
            )
        ]
    
    def __str__(self):
        return f"{self.organization.name} - {self.name}"
    
    def clean(self):
        """Validate department data"""
        super().clean()
        if self.code:
            self.code = self.code.upper().strip()

# Identity provider choices for SSO
IDENTITY_PROVIDER_CHOICES = [
    ('local', _('Local Authentication')),
    ('google', _('Google')),
    ('facebook', _('Facebook')),
    ('azuread', _('Microsoft Azure AD')),
    ('okta', _('Okta')),
    ('github', _('GitHub')),
    ('linkedin', _('LinkedIn')),
    ('oidc', _('Generic OIDC')),
    ('saml', _('SAML')),
]

class UserProfile(TimeStampedModel):
    """Extended user profile with SSO and organizational information"""
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile',
        verbose_name=_('User')
    )
    
    # Organizational Information
    employee_id = models.CharField(
        max_length=50,
        unique=True,
        null=True,
        blank=True,
        verbose_name=_('Employee ID'),
        help_text=_('Organization-specific employee identifier')
    )
    department = models.ForeignKey(
        Department,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='members',
        verbose_name=_('Department')
    )
    
    # Contact Information
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        verbose_name=_('Phone Number'),
        help_text=_('Format: +1234567890')
    )
    job_title = models.CharField(
        max_length=100,
        blank=True,
        verbose_name=_('Job Title')
    )
    avatar = models.FileField(
        upload_to='avatars/%Y/%m/%d/',
        null=True,
        blank=True,
        verbose_name=_('Avatar'),
        validators=[
            FileExtensionValidator(
                allowed_extensions=['jpg', 'jpeg', 'png', 'gif'],
                message=_('Only image files (JPG, PNG, GIF) are allowed')
            )
        ],
        help_text=_('Profile picture. Recommended size: 150x150 pixels')
    )
    
    # SSO/Identity Provider Information
    external_id = models.CharField(
        max_length=255,
        blank=True,
        db_index=True,
        verbose_name=_('External ID'),
        help_text=_('Unique identifier from external identity provider')
    )
    identity_provider = models.CharField(
        max_length=50,
        choices=IDENTITY_PROVIDER_CHOICES,
        default='local',
        db_index=True,
        verbose_name=_('Identity Provider')
    )
    
    # Additional metadata
    last_login_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Last Login At')
    )
    email_verified = models.BooleanField(
        default=False,
        verbose_name=_('Email Verified'),
        help_text=_('Whether the user has verified their email address')
    )
    mfa_enabled = models.BooleanField(
        default=False,
        verbose_name=_('MFA Enabled'),
        help_text=_('Whether multi-factor authentication is enabled')
    )
    preferred_language = models.CharField(
        max_length=10,
        default='en',
        verbose_name=_('Preferred Language'),
        help_text=_('Language code (e.g., en, es, fr)')
    )
    timezone = models.CharField(
        max_length=50,
        default='UTC',
        verbose_name=_('Timezone'),
        help_text=_('User timezone (e.g., America/New_York)')
    )
    
    class Meta:
        verbose_name = _('User Profile')
        verbose_name_plural = _('User Profiles')
        indexes = [
            models.Index(fields=['employee_id']),
            models.Index(fields=['external_id', 'identity_provider']),
            models.Index(fields=['identity_provider']),
            models.Index(fields=['email_verified']),
            models.Index(fields=['department']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['external_id', 'identity_provider'],
                name='unique_external_identity',
                condition=models.Q(external_id__gt='')
            ),
        ]
    
    def __str__(self):
        return f"{self.user.email} ({self.identity_provider})"
    
    def clean(self):
        """Validate profile data and ensure consistency"""
        super().clean()
        
        # Validate SSO data consistency
        if self.external_id and self.identity_provider == 'local':
            raise ValidationError({
                'identity_provider': _('External ID cannot be set with local identity provider')
            })
        
        if self.identity_provider != 'local' and not self.external_id:
            raise ValidationError({
                'external_id': _(f'External ID is required for {self.get_identity_provider_display()} authentication')
            })
        
        # Clean phone number format
        if self.phone_number:
            # Remove all non-digit characters except leading +
            import re
            if self.phone_number.startswith('+'):
                self.phone_number = '+' + re.sub(r'\D', '', self.phone_number[1:])
            else:
                self.phone_number = re.sub(r'\D', '', self.phone_number)
    
    @property
    def organization(self):
        """Get user's organization through department"""
        if self.department:
            return self.department.organization
        return None
    
    @property
    def full_name(self):
        """Get user's full name"""
        return self.user.get_full_name()
    
    def update_last_login(self):
        """Update last login timestamp in profile"""
        from django.utils.timezone import now
        self.last_login_at = now()
        self.save(update_fields=['last_login_at', 'updated_at'])


# Signal handlers for automatic profile creation and cleanup
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    """
    Create or update user profile when User is saved
    """
    if created:
        UserProfile.objects.create(user=instance)
    else:
        # Ensure profile exists (handles edge cases)
        if not hasattr(instance, 'profile'):
            UserProfile.objects.create(user=instance)
        else:
            instance.profile.save()