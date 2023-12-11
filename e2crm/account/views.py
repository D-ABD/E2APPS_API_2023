# account/views.py
from django.http import JsonResponse
from drf_yasg.utils import swagger_auto_schema
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny
from .permissions import IsOwnerOrReadOnly
from django.contrib.auth.hashers import check_password
from django.contrib.auth import update_session_auth_hash

from .models import CustomUser
from rest_framework import generics, status
from rest_framework.response import Response

from .serializers import CustomUserSerializer, RegisterSerializer, LoginSerializer, LogoutSerializer


class UserDetail(generics.RetrieveUpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]


class RegisterView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=RegisterSerializer,  # Spécifiez le serializer pour le corps de la requête
        responses={status.HTTP_201_CREATED: CustomUserSerializer()},  # Spécifiez la réponse pour le statut 201
    )
    def create(self, request, *args, **kwargs):
        """
        Register a new user.

        This API endpoint allows users to register a new account.

        ---
        # Paramètres
        - username: The username for the new user.
        - email: The email for the new user.
        - password: The password for the new user.

        # Réponses
        - 201: Created - The user has been successfully registered.
        - 400: Bad Request - If there is an error in the registration process.
        """
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            print("Erreur lors de la validation du serializer:", e)
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        data = CustomUserSerializer(user).data
        data['access'] = access_token

        return Response(data, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Log in a user.

        This API endpoint allows users to log in to their account.

        ---
        # Paramètres
        - username: The username for the user.
        - password: The password for the user.

        # Réponses
        - 200: OK - Successful login. Returns access and refresh tokens.
        - 400: Bad Request - If there is an error in the login process.
        """
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({"error": "Invalid username or password"}, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data['user']

        if not user.is_active:
            return Response({"error": "This account is inactive"}, status=status.HTTP_400_BAD_REQUEST)

        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token

        return Response({
            'refresh': str(refresh),
            'access': str(access_token),
        })


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)

        if serializer.is_valid():
            refresh_token = serializer.validated_data['refresh_token']

            try:
                RefreshToken(refresh_token).blacklist()
                # Ajout d'un message détaillé pour le succès de la déconnexion
                return JsonResponse(
                    {"success": "User logged out successfully.", "message": "The refresh token has been blacklisted."},
                    status=status.HTTP_200_OK
                )
            except TokenError:
                # Ajout d'un message détaillé pour un token invalide
                return JsonResponse(
                    {"error": "Invalid refresh token", "message": "The provided refresh token is invalid or expired."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            # Ajout d'un message détaillé pour les erreurs de validation
            return JsonResponse(
                {"error": "Bad request", "message": "Invalid data received.", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Change user's password.

        This API endpoint allows an authenticated user to change their password.

        ---
        # Paramètres
        - current_password: The user's current password.
        - new_password: The new password for the user.

        # Réponses
        - 200: OK - Password changed successfully.
        - 400: Bad Request - If there is an error in the password change process.
        """
        user = request.user
        current_password = request.data.get('current_password', '')
        new_password = request.data.get('new_password', '')

        if not check_password(current_password, user.password):
            return Response({"error": "Current password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        update_session_auth_hash(request, user)

        return Response({"success": "Password changed successfully."}, status=status.HTTP_200_OK)


class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        """
        Delete user's account.

        This API endpoint allows an authenticated user to delete their account.

        ---
        # Réponses
        - 204: No Content - User account deleted successfully.
        """
        user = request.user
        user.delete()
        return Response({"success": "User account deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
