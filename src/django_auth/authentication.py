"""Identity supplied by the Roll Pastuch authentication proxy.

The platform signs people in before a request reaches Django and forwards the
result as ``X-Authentik-*`` headers. Applications have no local user table,
passwords, login page, or authentication routes.

Every view requires a signed-in identity unless explicitly marked ``@public``.
During local development, ``MOCK_USER_*`` Django settings provide a stand-in
identity, but only while ``DEBUG`` is enabled.
"""

from dataclasses import dataclass
from functools import wraps
from typing import Any

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse
from inertia import share


@dataclass(frozen=True)
class Identity:
    """The signed-in person exposed on every request as ``request.identity``."""

    subject: str
    email: str
    name: str
    roles: tuple[str, ...]

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def as_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "email": self.email,
            "name": self.name,
            "roles": list(self.roles),
        }


def identity_from_proxy(request: HttpRequest) -> Identity | None:
    """Read the identity added to the request by the platform proxy."""

    subject = request.META.get("HTTP_X_AUTHENTIK_UID", "").strip()
    if not subject:
        return None

    email = request.META.get("HTTP_X_AUTHENTIK_EMAIL", "").strip()
    username = request.META.get("HTTP_X_AUTHENTIK_USERNAME", "").strip()
    name = request.META.get("HTTP_X_AUTHENTIK_NAME", "").strip()
    groups = request.META.get("HTTP_X_AUTHENTIK_GROUPS", "")
    return Identity(
        subject=subject,
        email=email,
        name=name or username or email or subject,
        roles=tuple(sorted(role.strip() for role in groups.split("|") if role.strip())),
    )


def mock_identity() -> Identity | None:
    """Return the stand-in identity used exclusively during local development."""

    email = getattr(settings, "MOCK_USER_EMAIL", "")
    if not settings.DEBUG or not email:
        return None

    name = getattr(settings, "MOCK_USER_NAME", "")
    roles = getattr(settings, "MOCK_USER_ROLES", ())
    return Identity(
        subject=email,
        email=email,
        name=name or email,
        roles=tuple(roles),
    )


def public(view):
    """Allow signed-out visitors to open this view."""

    view.is_public = True
    return view


class IdentityMiddleware:
    """Attach the platform identity and require it by default."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        identity = identity_from_proxy(request) or mock_identity()
        request.identity = identity
        share(request, auth={"user": identity.as_dict() if identity else None})
        return self.get_response(request)

    def process_view(self, request, view, view_args, view_kwargs):
        if request.identity is None and not getattr(view, "is_public", False):
            return HttpResponse(status=401)
        return None


def require_role(role: str):
    """Require a platform role before calling a view."""

    def decorator(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if request.identity is None or not request.identity.has_role(role):
                raise PermissionDenied(f"This page needs the '{role}' role.")
            return view(request, *args, **kwargs)

        return wrapped

    return decorator
