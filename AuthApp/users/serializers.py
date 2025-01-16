from rest_framework.serializers import (
    ModelSerializer,
    Serializer,
    CharField,
    EmailField,
    UniqueTogetherValidator,
)
from rest_framework.exceptions import ValidationError

from django.contrib.auth import get_user_model

from .models import RefreshToken

# from datetime import datetime, UTC


class PlaceholderSerializer(Serializer):
    pass


class RegisterSerializer(ModelSerializer):

    email = EmailField()
    password = CharField()

    class Meta:
        model = get_user_model()
        fields = ['id', 'username', 'email', 'password']
        extra_kwargs = {'password':
                            {'write_only': True},
                        'email':
                            {'required': True},
                        }
        validators = [
            UniqueTogetherValidator(
                queryset=model.objects.all(),
                fields=['email'],
            )
        ]

    def create(self, validated_data):
        # In case we want to generate placeholder usernames
        # if not (username := validated_data.get('username', '')):
        #     validated_data['username'] =
        #     f'user{int(datetime.now(UTC).timestamp())}'
        password = validated_data.pop('password')
        if not password:
            raise ValidationError()
        username = validated_data.pop('username', '')
        model = self.Meta.model(username=username, **validated_data)
        model.set_password(password)
        model.save()
        return model


class LoginSerializer(Serializer):
    email = EmailField()
    password = CharField()


class LogoutSerializer(Serializer):
    refresh_token = CharField()


class TokenRefreshSerializer(Serializer):
    refresh_token = CharField()


class ProfileSerializer(ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ['id', 'username', 'email']


class MeDataChangeSerializer(ModelSerializer):
    username = CharField()

    class Meta:
        model = get_user_model()
        fields = ['id', 'username', 'email']
