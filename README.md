# Roll Pastuch Django authentication

The shared OpenID Connect boundary for Django applications on the Roll Pastuch
platform. Authentik remains the user directory; applications receive only a
small immutable identity in `request.identity` and Inertia's `auth` prop.

The package provides no user model, passwords, admin integration, or login UI.
It owns the OIDC authorization-code callback and requires authentication on all
views unless they are marked `@public`.

Applications add the middleware and one URL include:

```python
"django_auth.IdentityMiddleware"
```

```python
path("_auth/", include("django_auth.urls"))
```

Deployments provide three environment variables:

```text
OIDC_ISSUER_URL=https://auth.example/application/o/my-app/
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
```

The Authentik provider uses the `openid profile email` scopes and must register
`https://<application-host>/_auth/callback` as a strict redirect URI. Authlib
handles discovery, state, nonce, PKCE, token exchange, and ID-token validation.
Only `sub`, `email`, `name`, and the Authentik `groups` claim are retained in the
application session.

For local development only, `MOCK_USER_EMAIL`, `MOCK_USER_NAME`, and
`MOCK_USER_ROLES` provide a stand-in identity while Django `DEBUG` is enabled.

Application tests authenticate without provider-specific headers:

```python
from django_auth.testing import sign_in

sign_in(self.client, roles=("admin",))
```
