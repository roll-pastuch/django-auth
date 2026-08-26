from django.urls import path

from . import views

app_name = "django_auth"

urlpatterns = [
    path("login", views.login, name="login"),
    path("callback", views.callback, name="callback"),
]
