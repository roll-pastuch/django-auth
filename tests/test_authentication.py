from django.test import RequestFactory, SimpleTestCase, override_settings

from django_auth import Identity, identity_from_proxy, mock_identity


SIGNED_IN = {
    "HTTP_X_AUTHENTIK_USERNAME": "ada",
    "HTTP_X_AUTHENTIK_GROUPS": "admin|member",
    "HTTP_X_AUTHENTIK_EMAIL": "ada@example.com",
    "HTTP_X_AUTHENTIK_NAME": "Ada Admin",
    "HTTP_X_AUTHENTIK_UID": "user-123",
}


class IdentityTests(SimpleTestCase):
    def test_proxy_headers_become_an_identity(self):
        request = RequestFactory().get("/", **SIGNED_IN)

        self.assertEqual(
            identity_from_proxy(request),
            Identity(
                subject="user-123",
                email="ada@example.com",
                name="Ada Admin",
                roles=("admin", "member"),
            ),
        )

    def test_subject_is_required(self):
        request = RequestFactory().get("/", HTTP_X_AUTHENTIK_EMAIL="ada@example.com")
        self.assertIsNone(identity_from_proxy(request))

    @override_settings(
        DEBUG=True,
        MOCK_USER_EMAIL="dev@example.com",
        MOCK_USER_NAME="Dev",
        MOCK_USER_ROLES=["member"],
    )
    def test_mock_identity_is_available_during_development(self):
        self.assertEqual(
            mock_identity(),
            Identity("dev@example.com", "dev@example.com", "Dev", ("member",)),
        )

    @override_settings(DEBUG=False, MOCK_USER_EMAIL="dev@example.com")
    def test_mock_identity_is_disabled_outside_debug_mode(self):
        self.assertIsNone(mock_identity())


class AccessTests(SimpleTestCase):
    def test_private_view_rejects_anonymous_requests(self):
        self.assertEqual(self.client.get("/private").status_code, 401)

    def test_public_view_allows_anonymous_requests(self):
        self.assertEqual(self.client.get("/public").status_code, 200)

    def test_private_view_receives_the_identity(self):
        response = self.client.get("/private", **SIGNED_IN)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"user-123")

    def test_role_view_allows_the_required_role(self):
        self.assertEqual(self.client.get("/admin", **SIGNED_IN).status_code, 200)

    def test_role_view_rejects_the_wrong_role(self):
        headers = {**SIGNED_IN, "HTTP_X_AUTHENTIK_GROUPS": "member"}
        self.assertEqual(self.client.get("/admin", **headers).status_code, 403)
