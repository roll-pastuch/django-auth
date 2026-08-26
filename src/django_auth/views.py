"""Package-owned endpoints for the OpenID Connect authorization-code flow."""

from authlib.integrations.base_client.errors import OAuthError
from django.http import HttpResponseBadRequest
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_GET

from .authentication import (
    EXPIRY_SESSION_KEY,
    IDENTITY_SESSION_KEY,
    identity_from_claims,
    public,
)
from .oidc import get_oidc_client

NEXT_SESSION_KEY = "django_auth.next"


def _safe_next(request, value: str | None) -> str:
    if value and url_has_allowed_host_and_scheme(
        value,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return value
    return "/"


@public
@require_GET
def login(request):
    """Redirect the browser to Authentik."""

    request.session[NEXT_SESSION_KEY] = _safe_next(request, request.GET.get("next"))
    callback_url = request.build_absolute_uri(reverse("django_auth:callback"))
    return get_oidc_client().authorize_redirect(request, callback_url)


@public
@require_GET
def callback(request):
    """Validate the OIDC response and establish the application session."""

    try:
        token = get_oidc_client().authorize_access_token(request)
        identity = identity_from_claims(token["userinfo"])
    except (KeyError, OAuthError, ValueError):
        return HttpResponseBadRequest("OpenID Connect authentication failed.")

    request.session.cycle_key()
    request.session[IDENTITY_SESSION_KEY] = identity.as_dict()
    expires_at = token.get("expires_at") or token["userinfo"].get("exp")
    if expires_at is not None:
        request.session[EXPIRY_SESSION_KEY] = float(expires_at)

    return redirect(request.session.pop(NEXT_SESSION_KEY, "/"))
