# account/serializers.py

from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model

User = get_user_model()


# Serializer pour le modèle CustomUser, utilisé pour représenter les utilisateurs dans l'API
class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'bio', 'avatar']


# Serializer pour l'inscription d'un nouvel utilisateur
class RegisterSerializer(serializers.ModelSerializer):
    # Champ de mot de passe requis pour l'inscription
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']

    # Méthode pour créer un nouvel utilisateur à partir des données validées
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user


# Serializer pour la connexion d'un utilisateur existant
class LoginSerializer(serializers.Serializer):
    # Champs requis pour la connexion
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    # Méthode pour valider les données de connexion
    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            # Authentification de l'utilisateur
            user = authenticate(username=username, password=password)

            if user:
                if not user.is_active:
                    msg = 'User account is disabled.'
                    raise serializers.ValidationError(msg)
            else:
                msg = 'Unable to log in with provided credentials.'
                raise serializers.ValidationError(msg)
        else:
            msg = 'Must include "username" and "password".'
            raise serializers.ValidationError(msg)

        # Ajout de l'utilisateur validé aux données pour un accès ultérieur
        data['user'] = user
        print("User validated:", user)  # Ajoutez cette ligne pour déboguer
        return data


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()
