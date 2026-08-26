# Roll Pastuch Django authentication

The shared authentication boundary for Django applications on the Roll Pastuch
platform.

It trusts the identity headers added by the platform's Authentik proxy, exposes
that identity as `request.identity`, and requires authentication by default. It
does not add users, passwords, login views, routes, models, or migrations.

Applications use the public API directly:

```python
from django_auth import public, require_role
```

and add the middleware after Django's standard middleware and before Inertia:

```python
"django_auth.IdentityMiddleware"
```

The platform must remove incoming `X-Authentik-*` headers and add its own before
forwarding requests to Django. The package must not be exposed directly to
untrusted traffic.

For local development only, an identity can be supplied with the Django settings
`MOCK_USER_EMAIL`, `MOCK_USER_NAME`, and `MOCK_USER_ROLES`. Mock identities are
ignored unless `DEBUG` is enabled.
