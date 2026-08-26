"""Minimal platform authentication for Django applications."""

from .authentication import (
    Identity,
    IdentityMiddleware,
    identity_from_proxy,
    mock_identity,
    public,
    require_role,
)

__all__ = [
    "Identity",
    "IdentityMiddleware",
    "identity_from_proxy",
    "mock_identity",
    "public",
    "require_role",
]
