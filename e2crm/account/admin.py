from django.contrib import admin
from .models import CustomUser

# Enregistrez votre modèle CustomUser pour qu'il soit visible dans l'interface d'administration
admin.site.register(CustomUser)
