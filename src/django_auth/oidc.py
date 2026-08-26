"""Small Authlib client configured for the platform's OIDC provider."""

import os
from dataclasses import dataclass
from functools import lru_cache

from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


@dataclass(frozen=True)
class OIDCConfiguration:
    issuer: str
    client_id: str
    client_secret: str

    @property
    def metadata_url(self) -> str:
        return f"{self.issuer.rstrip('/')}/.well-known/openid-configuration"


def _value(name: str) -> str:
    return str(getattr(settings, name, "") or os.environ.get(name, "")).strip()


def get_configuration() -> OIDCConfiguration:
    configuration = OIDCConfiguration(
        issuer=_value("OIDC_ISSUER_URL"),
        client_id=_value("OIDC_CLIENT_ID"),
        client_secret=_value("OIDC_CLIENT_SECRET"),
    )
    missing = [
        name
        for name, value in (
            ("OIDC_ISSUER_URL", configuration.issuer),
            ("OIDC_CLIENT_ID", configuration.client_id),
            ("OIDC_CLIENT_SECRET", configuration.client_secret),
        )
        if not value
    ]
    if missing:
        raise ImproperlyConfigured(
            "Missing OpenID Connect configuration: " + ", ".join(missing)
        )
    return configuration


@lru_cache(maxsize=16)
def _build_client(configuration: OIDCConfiguration):
    oauth = OAuth()
    return oauth.register(
        "authentik",
        client_id=configuration.client_id,
        client_secret=configuration.client_secret,
        server_metadata_url=configuration.metadata_url,
        client_kwargs={
            "scope": "openid profile email",
            "code_challenge_method": "S256",
        },
    )


def get_oidc_client():
    return _build_client(get_configuration())
