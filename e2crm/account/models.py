# account/models.py

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import MaxLengthValidator, FileExtensionValidator


# Définition d'un modèle utilisateur personnalisé qui étend AbstractUser
class CustomUser(AbstractUser):
    # Champ pour stocker l'image de profil de l'utilisateur
    avatar = models.ImageField(
        upload_to='avatars/',
        blank=True,
        null=True,
        verbose_name='Image de profil',
        validators=[
            FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png']),
            MaxLengthValidator(limit_value=1024 * 1024, message='File size must be at most 1 MB.'),
        ]
    )

    # Champ pour stocker la biographie de l'utilisateur
    bio = models.TextField(
        blank=True,
        null=True,
        verbose_name='Biographie',
        validators=[
            MaxLengthValidator(limit_value=500, message='Bio should be at most 500 characters.'),
        ]
    )

    # Méthode qui retourne la représentation en chaîne de l'objet utilisateur
    def __str__(self):
        return self.username
