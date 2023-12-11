# account/urls.py
from django.contrib.auth.views import LogoutView
from django.urls import path

from .views import RegisterView, UserDetail, LoginView, ChangePasswordView, DeleteAccountView

app_name = 'account'


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('user/<int:pk>/', UserDetail.as_view(), name='user-detail'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('delete-account/', DeleteAccountView.as_view(), name='delete-account'),

]






