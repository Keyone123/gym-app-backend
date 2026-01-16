from django.urls import path
from .views import UserCreateView, LoginView, MeView

urlpatterns = [
    path("register/", UserCreateView.as_view()),
    path("login/", LoginView.as_view()),
    path("me/", MeView.as_view()),
]
