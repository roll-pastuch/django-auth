"""Stable testing contract for application test suites."""

from django.test import Client

from .authentication import EXPIRY_SESSION_KEY, IDENTITY_SESSION_KEY, Identity


def sign_in(
    client: Client,
    identity: Identity | None = None,
    *,
    subject: str = "test-user",
    email: str = "test@example.com",
    name: str = "Test User",
    roles: tuple[str, ...] = ("member",),
) -> Identity:
    """Establish a package-owned authenticated session for a Django test client."""

    identity = identity or Identity(subject, email, name, roles)
    session = client.session
    session[IDENTITY_SESSION_KEY] = identity.as_dict()
    session.pop(EXPIRY_SESSION_KEY, None)
    session.save()
    return identity
