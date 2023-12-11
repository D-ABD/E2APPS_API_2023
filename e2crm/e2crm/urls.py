# account/urls.py
from django.urls import path, include, re_path
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static

from .views import index, authenticated_view

# Configuration de Swagger pour documenter l'API
# Ceci permet de générer une interface utilisateur pour visualiser et interagir avec l'API.
schema_view = get_schema_view(
    openapi.Info(
        title="E2CRM API",
        default_version='v1',
        description="Description de mon API",
        terms_of_service="https://www.monapi.com/terms/",
        contact=openapi.Contact(email="contact@monapi.com"),
        license=openapi.License(name="Licence BSD"),
    ),
    public=True,
)

app_name = 'e2crm'

urlpatterns = [
    # Interfaces utilisateur de Swagger et Redoc, pour la documentation de l'API
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),

    # Inclut les URL de l'application 'account'
        path('account/', include('account.urls', namespace='account')),

    # URL pour l'interface d'administration Django
    path('admin/', admin.site.urls),

    # Chemin d'accès pour la page d'accueil de l'application
    path('', index, name="home"),

    # Chemin vers vue authentifiée pour test
    path('authenticated/', authenticated_view, name='authenticated_view'),

    ]

# Configuration pour servir les fichiers médias en mode DEBUG
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)














