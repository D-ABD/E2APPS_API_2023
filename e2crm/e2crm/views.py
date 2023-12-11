from django.shortcuts import render
from rest_framework.permissions import IsAuthenticated


def index(request):
    return render(request, "index.html")


def authenticated_view(request):
    # Utilisez la permission IsAuthenticated pour restreindre l'accès aux utilisateurs authentifiés
    permission_classes = [IsAuthenticated]
    return render(request, 'authenticated_view.html')
