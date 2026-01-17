from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.db import IntegrityError

User = get_user_model()


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = User
        fields = ("id", "username", "email", "password", "isAdmin")

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email já está em uso")
        return value

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username já está em uso")
        return value

    def create(self, validated_data):
        try:
            user = User.objects.create_user(
                username=validated_data["username"],
                email=validated_data["email"],
                password=validated_data["password"],
                isAdmin=validated_data.get("isAdmin", False),
            )
        except IntegrityError:
            raise serializers.ValidationError(
                {"detail": "Erro ao criar usuário"}
            )

        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email")
