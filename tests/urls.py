from django.http import HttpResponse
from django.urls import path

from django_auth import public, require_role


def private_view(request):
    return HttpResponse(request.identity.subject)


@public
def public_view(request):
    return HttpResponse("public")


@require_role("admin")
def admin_view(request):
    return HttpResponse("admin")


urlpatterns = [
    path("private", private_view),
    path("public", public_view),
    path("admin", admin_view),
]
