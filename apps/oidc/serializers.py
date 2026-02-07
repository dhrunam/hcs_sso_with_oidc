from rest_framework import serializers
from oauth2_provider.models import Application
from django.core.validators import URLValidator
import json

class IntrospectionRequestSerializer(serializers.Serializer):
    """Serializer for token introspection requests (RFC 7662)"""
    token = serializers.CharField(required=True, trim_whitespace=False)
    token_type_hint = serializers.ChoiceField(
        choices=['access_token', 'refresh_token'],
        default='access_token',
        required=False
    )
    client_id = serializers.CharField(required=True)
    client_secret = serializers.CharField(required=True, write_only=True, trim_whitespace=False)
    
    def validate(self, data):
        """Validate client credentials"""
        from oauth2_provider.models import Application
        
        try:
            app = Application.objects.get(client_id=data['client_id'])
            if app.client_secret != data['client_secret']:
                raise serializers.ValidationError("Invalid client credentials")
            data['application'] = app
        except Application.DoesNotExist:
            raise serializers.ValidationError("Invalid client credentials")
        return data


class RevocationRequestSerializer(serializers.Serializer):
    """Serializer for token revocation requests (RFC 7009)"""
    token = serializers.CharField(required=True, trim_whitespace=False)
    token_type_hint = serializers.ChoiceField(
        choices=['access_token', 'refresh_token'],
        required=False
    )
    client_id = serializers.CharField(required=True)
    client_secret = serializers.CharField(required=True, write_only=True, trim_whitespace=False)


class ClientRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for OIDC dynamic client registration (RFC 7591)"""
    redirect_uris = serializers.ListField(
        child=serializers.URLField(),
        required=True,
        help_text="Array of redirect URIs for the client"
    )
    grant_types = serializers.ListField(
        child=serializers.ChoiceField(choices=[
            'authorization_code', 'implicit', 'password', 
            'client_credentials', 'refresh_token'
        ]),
        default=['authorization_code', 'refresh_token'],
        required=False
    )
    response_types = serializers.ListField(
        child=serializers.ChoiceField(choices=[
            'code', 'token', 'id_token', 'code token', 
            'code id_token', 'token id_token', 'code token id_token'
        ]),
        default=['code'],
        required=False
    )
    application_type = serializers.ChoiceField(
        choices=['web', 'native'],
        default='web',
        required=False
    )
    token_endpoint_auth_method = serializers.ChoiceField(
        choices=['client_secret_basic', 'client_secret_post', 'none'],
        default='client_secret_basic',
        required=False
    )
    scope = serializers.CharField(
        required=False,
        default='openid profile email',
        help_text="Space-separated list of scopes"
    )
    
    # Optional metadata fields
    client_uri = serializers.URLField(required=False)
    logo_uri = serializers.URLField(required=False)
    tos_uri = serializers.URLField(required=False)
    policy_uri = serializers.URLField(required=False)
    jwks_uri = serializers.URLField(required=False)
    jwks = serializers.JSONField(required=False, help_text="JSON Web Key Set")
    contacts = serializers.ListField(
        child=serializers.EmailField(),
        required=False
    )
    
    class Meta:
        model = Application
        fields = [
            'client_name', 'redirect_uris', 'grant_types', 'response_types',
            'application_type', 'token_endpoint_auth_method', 'scope',
            'client_uri', 'logo_uri', 'tos_uri', 'policy_uri', 
            'jwks_uri', 'jwks', 'contacts'
        ]
        extra_kwargs = {
            'client_name': {'source': 'name'}
        }
    
    def validate_redirect_uris(self, value):
        """Validate redirect URIs"""
        if len(value) == 0:
            raise serializers.ValidationError("At least one redirect URI is required")
        
        validator = URLValidator()
        for uri in value:
            try:
                validator(uri)
            except:
                raise serializers.ValidationError(f"Invalid URL: {uri}")
        
        return value
    
    def create(self, validated_data):
        """Create application with dynamic registration"""
        request = self.context.get('request')
        
        # Extract list fields
        redirect_uris = ' '.join(validated_data.pop('redirect_uris'))
        grant_types = validated_data.pop('grant_types', [])
        response_types = validated_data.pop('response_types', [])
        contacts = validated_data.pop('contacts', [])
        
        # Determine grant type
        if 'authorization_code' in grant_types:
            authorization_grant_type = 'authorization-code'
        elif 'implicit' in grant_types:
            authorization_grant_type = 'implicit'
        elif 'password' in grant_types:
            authorization_grant_type = 'password'
        elif 'client_credentials' in grant_types:
            authorization_grant_type = 'client-credentials'
        else:
            authorization_grant_type = 'authorization-code'
        
        # Create the application
        application = Application.objects.create(
            name=validated_data.pop('client_name'),
            user=request.user if request and request.user.is_authenticated else None,
            client_type='confidential' if validated_data.get('token_endpoint_auth_method') != 'none' else 'public',
            authorization_grant_type=authorization_grant_type,
            redirect_uris=redirect_uris,
            skip_authorization=False,
            **{k: v for k, v in validated_data.items() if hasattr(Application, k)}
        )
        
        # Store additional metadata in JSON field if available
        if contacts:
            application.data = json.dumps({'contacts': contacts})
            application.save()
        
        return application


class SessionSerializer(serializers.Serializer):
    """Serializer for session information"""
    id = serializers.IntegerField(read_only=True)
    application = serializers.CharField(source='application.name', read_only=True)
    scopes = serializers.SerializerMethodField(read_only=True)
    created = serializers.DateTimeField(read_only=True)
    expires = serializers.DateTimeField(read_only=True)
    identity_provider = serializers.SerializerMethodField(read_only=True)
    
    def get_scopes(self, obj):
        return obj.scope.split()
    
    def get_identity_provider(self, obj):
        return getattr(obj, 'identity_provider', 'local')