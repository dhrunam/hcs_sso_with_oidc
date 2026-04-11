import re

from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import AuthenticationForm

from apps.core.models import UserProfile


class PhoneNumberAuthenticationForm(AuthenticationForm):
    """Authenticate users using phone number + password only."""

    username = forms.CharField(
        label='Phone Number',
        max_length=20,
        widget=forms.TextInput(attrs={'autofocus': True}),
    )

    error_messages = {
        'invalid_login': 'Invalid phone number or password. Phone number must be 9-15 digits (e.g., +1234567890 or 1234567890).',
        'invalid_phone_format': 'Phone number must contain 9-15 digits. Format: +1234567890 or 1234567890',
        'phone_not_found': 'No account found with this phone number.',
        'inactive': 'This account is inactive.',
    }

    @staticmethod
    def _normalize_phone(value: str) -> str:
        value = (value or '').strip()
        if value.startswith('+'):
            return '+' + re.sub(r'\D', '', value[1:])
        return re.sub(r'\D', '', value)

    @staticmethod
    def _is_phone_like(value: str) -> bool:
        """Strict validation: input must be 9-15 digits with optional leading +."""
        normalized = PhoneNumberAuthenticationForm._normalize_phone(value)
        digits = normalized[1:] if normalized.startswith('+') else normalized
        return digits.isdigit() and 9 <= len(digits) <= 15

    def clean(self):
        phone_number = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if not phone_number or not password:
            return self.cleaned_data

        # Strict phone-format validation: reject non-phone inputs immediately
        if not self._is_phone_like(phone_number):
            raise forms.ValidationError(
                self.error_messages['invalid_phone_format'],
                code='invalid_phone_format',
            )

        # Extract only digits
        digits_only = re.sub(r'\D', '', phone_number)
        
        # Create all candidate formats to match against database
        candidates = set()
        
        # Add original (might have spaces or hyphens)
        candidates.add(phone_number.strip())
        
        # Add plain digits version
        if digits_only:
            candidates.add(digits_only)
            
            # Add + prefixed version
            if len(digits_only) == 10:
                # Could be US (add +1 prefix) or missing country code
                candidates.add( digits_only)
            else:
                # For non-10-digit, always try with +
                candidates.add( digits_only)
            
            # For numbers starting with country code +1, also try without it
            if digits_only.startswith('1') and len(digits_only) == 11:
                candidates.add(digits_only[1:])  # Remove country code
                
        profile = UserProfile.objects.filter(phone_number__in=list(candidates)).select_related('user').first()

        if not profile or not profile.user:
            raise forms.ValidationError(
                self.error_messages['phone_not_found'],
                code='phone_not_found',
            )

        self.user_cache = authenticate(
            self.request,
            username=profile.user.username,
            password=password,
        )

        if self.user_cache is None:
            raise self.get_invalid_login_error()
        self.confirm_login_allowed(self.user_cache)

        return self.cleaned_data
