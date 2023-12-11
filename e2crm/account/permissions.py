from rest_framework import permissions


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Permission personnalisée permettant uniquement aux propriétaires d'un objet de le modifier.
    Seuls les super utilisateurs ont tous les droits.
    """

    def has_object_permission(self, request, view, obj):
        # Seuls les super utilisateurs ont tous les droits
        if request.user and request.user.is_superuser:
            return True

        # Les propriétaires ont des droits complets, les autres ont des droits en lecture seule
        return obj == request.user or request.method in permissions.SAFE_METHODS
