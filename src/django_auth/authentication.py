"""Application identity backed by an OpenID Connect session."""

from dataclasses import dataclass
from functools import wraps
from time import time
from typing import Any, Mapping
from urllib.parse import urlencode

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from inertia import location, share

IDENTITY_SESSION_KEY = "django_auth.identity"
EXPIRY_SESSION_KEY = "django_auth.expires_at"


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


def identity_from_claims(claims: Mapping[str, Any]) -> Identity:
    """Reduce verified OIDC claims to the application's identity contract."""

    subject = str(claims.get("sub", "")).strip()
    if not subject:
        raise ValueError("The OpenID Connect identity has no subject.")

    email = str(claims.get("email", "")).strip()
    username = str(claims.get("preferred_username", "")).strip()
    name = str(claims.get("name", "")).strip()
    groups = claims.get("groups", ())
    if isinstance(groups, str):
        groups = (groups,)
    elif not isinstance(groups, (list, tuple, set)):
        groups = ()

    roles = {str(group).strip() for group in groups if str(group).strip()}

    return Identity(
        subject=subject,
        email=email,
        name=name or username or email or subject,
        roles=tuple(sorted(roles)),
    )


def identity_from_session(request: HttpRequest) -> Identity | None:
    """Read the identity established by the OIDC callback."""

    expires_at = request.session.get(EXPIRY_SESSION_KEY)
    if expires_at is not None and float(expires_at) <= time():
        request.session.pop(IDENTITY_SESSION_KEY, None)
        request.session.pop(EXPIRY_SESSION_KEY, None)
        return None

    value = request.session.get(IDENTITY_SESSION_KEY)
    if not isinstance(value, dict):
        return None

    try:
        return Identity(
            subject=str(value["subject"]),
            email=str(value["email"]),
            name=str(value["name"]),
            roles=tuple(str(role) for role in value["roles"]),
        )
    except (KeyError, TypeError):
        request.session.pop(IDENTITY_SESSION_KEY, None)
        return None


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
    """Attach the session identity and start OIDC when a private page needs it."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        identity = identity_from_session(request) or mock_identity()
        request.identity = identity
        share(request, auth={"user": identity.as_dict() if identity else None})
        return self.get_response(request)

    def process_view(self, request, view, view_args, view_kwargs):
        if request.identity is not None or getattr(view, "is_public", False):
            return None

        if request.method not in {"GET", "HEAD"}:
            return HttpResponse(status=401)

        query = urlencode({"next": request.get_full_path()})
        login_url = f"{reverse('django_auth:login')}?{query}"
        if request.headers.get("X-Inertia"):
            return location(request.build_absolute_uri(login_url))
        return redirect(login_url)


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
