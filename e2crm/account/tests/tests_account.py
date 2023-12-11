from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.reverse import reverse
from django.http import JsonResponse, HttpResponse


class AuthenticationTests(APITestCase):

    def create_user(self, username='testuser', email='testuser@example.com', password='testpassword'):
        user = get_user_model().objects.create_user(username=username, email=email, password=password)
        refresh = RefreshToken.for_user(user)
        user.access_token = str(refresh.access_token)
        return user

    def test_user_login(self):
        # Créer l'utilisateur
        created_user = self.create_user()

        url = reverse('account:login')
        data = {'username': 'testuser', 'password': 'testpassword'}

        # Ajouter l'en-tête d'autorisation
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {created_user.access_token}')

        response = self.client.post(url, data, format='json', HTTP_ACCEPT='application/json')
        print(response.content)  # Ajoutez cette ligne pour voir le contenu de la réponse

        # Ajoutez ces lignes pour voir les informations sur l'utilisateur
        print("Utilisateur actif:", created_user.is_active)
        print("Mot de passe vérifié:", created_user.check_password('testpassword'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_user_registration(self):
        url = reverse('account:register')
        data = {
            'username': 'testuser',  # Utiliser le même nom d'utilisateur que dans test_user_login
            'email': 'testuser@example.com',  # Utiliser le même e-mail que dans test_user_login
            'password': 'newpassword123'
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('access', response.data)  # Vérifier que le token d'accès est renvoyé

    def test_user_detail(self):
        # Créer l'utilisateur
        created_user = self.create_user()

        url = reverse('account:user-detail', args=[created_user.id])
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {created_user.access_token}')

        response = self.client.get(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'testuser')  # Vérifier que les détails sont corrects

    def test_user_update_profile(self):
        # Créer l'utilisateur
        created_user = self.create_user()

        url = reverse('account:user-detail', args=[created_user.id])
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {created_user.access_token}')

        data = {'username': 'updateduser', 'email': 'updateduser@example.com'}
        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Récupérer le dernier état de l'utilisateur depuis la base de données
        updated_user = get_user_model().objects.get(id=created_user.id)
        self.assertEqual(updated_user.username, 'updateduser')  # Vérifier que les modifications ont été apportées

    def test_user_update_profile_unauthorized(self):
        # Créer l'utilisateur
        created_user = self.create_user()

        url = reverse('account:user-detail', args=[created_user.id])

        # Ne pas ajouter l'en-tête d'autorisation pour simuler un utilisateur non authentifié
        response = self.client.patch(url, {'username': 'updateduser'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_change_password(self):
        url = reverse('account:change-password')
        data = {
            'current_password': 'testpassword',
            'new_password': 'newtestpassword'
        }

        # Utilisez create_user pour obtenir un utilisateur et son jeton d'accès
        created_user = self.create_user()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {created_user.access_token}')

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)

    def test_change_password_invalid_old_password(self):
        url = reverse('account:change-password')
        data = {
            'current_password': 'wrongpassword',
            'new_password': 'newtestpassword'
        }

        # Utilisez create_user pour obtenir un utilisateur et son jeton d'accès
        created_user = self.create_user()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {created_user.access_token}')

        response = self.client.post(url, data, format='json')
        print(response.content)  # Ajoutez cette ligne pour voir le contenu de la réponse

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Vérifiez que la clé 'non_field_errors' est présente dans la réponse
        self.assertIn('error', response.data)

        # Vérifiez le contenu de 'non_field_errors' pour s'assurer qu'il contient le message attendu
        self.assertEqual(response.data['error'], 'Current password is incorrect')

    def test_change_password_unauthorized(self):
        # Créer l'utilisateur
        created_user = self.create_user()

        url = reverse('account:change-password')

        # Ne pas ajouter l'en-tête d'autorisation pour simuler un utilisateur non authentifié
        response = self.client.post(url, {'current_password': 'testpassword', 'new_password': 'newtestpassword'},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class DeleteAccountTests(APITestCase):
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            username='testuser', email='test@example.com', password='testpassword'
        )
        self.refresh_token = str(RefreshToken.for_user(self.user))
        self.url = reverse('account:delete-account')

    def test_account_deletion(self):
        # Authenticate the user
        self.client.force_authenticate(user=self.user)

        # Send DELETE request
        response = self.client.delete(self.url)

        # Check if the response status is 204 NO CONTENT
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Check if the user is actually deleted
        self.assertFalse(self.user_model.objects.filter(username='testuser').exists())

    def test_unauthenticated_deletion_attempt(self):
        # Try to delete an account without authentication
        response = self.client.delete(self.url)

        # Check if the response status is 401 UNAUTHORIZED
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class LogoutViewTests(APITestCase):
    def create_user(self, username='testuser', email='testuser@example.com', password='testpassword'):
        user = get_user_model().objects.create_user(username=username, email=email, password=password)
        refresh = RefreshToken.for_user(user)
        user.access_token = str(refresh.access_token)
        return user

    def test_logout_successful(self):
        # Créer l'utilisateur
        created_user = self.create_user()

        # Connectez l'utilisateur en utilisant le token d'actualisation
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {created_user.access_token}')

        # Effectuer une demande POST à la vue de déconnexion
        url = reverse('account:logout')  # Assurez-vous d'avoir une URL appropriée pour la déconnexion
        response = self.client.post(url, format='json')

        # Vérifier que la réponse a le statut HTTP 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Vérifier que la réponse est de type HttpResponse
        self.assertIsInstance(response, HttpResponse)

        # Si la réponse est une page HTML, vérifiez si elle contient le message de déconnexion
        if 'text/html' in response.get('Content-Type', ''):
            self.assertContains(response, "Déconnecté")
        else:
            # Si la réponse n'est pas HTML, vérifiez le contenu JSON
            expected_data = {
                "success": "User logged out successfully.",
                "message": "The refresh token has been blacklisted."
            }
            self.assertJSONEqual(response.content, expected_data)

