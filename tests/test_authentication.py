import json
from time import time
from unittest.mock import Mock, patch

from django.http import HttpResponseRedirect
from django.test import TestCase, override_settings

from django_auth import Identity, identity_from_claims, mock_identity
from django_auth.authentication import EXPIRY_SESSION_KEY, IDENTITY_SESSION_KEY
from django_auth.testing import sign_in


ADA = Identity(
    subject="user-123",
    email="ada@example.com",
    name="Ada Admin",
    roles=("admin", "member"),
)


class IdentityTests(TestCase):
    def test_verified_claims_become_the_application_identity(self):
        self.assertEqual(
            identity_from_claims(
                {
                    "sub": "user-123",
                    "email": "ada@example.com",
                    "name": "Ada Admin",
                    "groups": ["member", "admin"],
                }
            ),
            ADA,
        )

    def test_subject_is_required(self):
        with self.assertRaises(ValueError):
            identity_from_claims({"email": "ada@example.com"})

    def test_username_is_used_when_name_is_missing(self):
        identity = identity_from_claims(
            {"sub": "user-123", "preferred_username": "ada"}
        )
        self.assertEqual(identity.name, "ada")

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


class AccessTests(TestCase):
    def test_private_page_starts_login(self):
        response = self.client.get("/private")
        self.assertRedirects(
            response,
            "/_auth/login?next=%2Fprivate",
            fetch_redirect_response=False,
        )

    def test_inertia_page_starts_a_full_page_login(self):
        response = self.client.get("/private", HTTP_X_INERTIA="true")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.headers["X-Inertia-Location"],
            "http://testserver/_auth/login?next=%2Fprivate",
        )

    def test_private_post_is_rejected_without_losing_it_to_a_redirect(self):
        self.assertEqual(self.client.post("/private").status_code, 401)

    def test_public_page_allows_anonymous_requests(self):
        self.assertEqual(self.client.get("/public").status_code, 200)

    def test_test_helper_establishes_the_same_session_as_oidc(self):
        sign_in(self.client, ADA)
        response = self.client.get("/private")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"user-123")

    def test_expired_identity_starts_login_again(self):
        session = self.client.session
        session[IDENTITY_SESSION_KEY] = ADA.as_dict()
        session[EXPIRY_SESSION_KEY] = time() - 1
        session.save()

        self.assertEqual(self.client.get("/private").status_code, 302)

    def test_identity_is_shared_with_inertia_pages(self):
        sign_in(self.client, ADA)
        response = self.client.get("/inertia", HTTP_X_INERTIA="true")
        self.assertEqual(
            json.loads(response.content)["props"]["auth"]["user"],
            ADA.as_dict(),
        )

    def test_role_view_allows_the_required_role(self):
        sign_in(self.client, ADA)
        self.assertEqual(self.client.get("/admin").status_code, 200)

    def test_role_view_rejects_the_wrong_role(self):
        sign_in(self.client, roles=("member",))
        self.assertEqual(self.client.get("/admin").status_code, 403)

    @override_settings(
        DEBUG=True,
        MOCK_USER_EMAIL="dev@example.com",
        MOCK_USER_NAME="Dev",
        MOCK_USER_ROLES=["member"],
    )
    def test_oidc_session_wins_over_the_development_identity(self):
        sign_in(self.client, ADA)
        self.assertEqual(self.client.get("/private").content, b"user-123")


class OIDCFlowTests(TestCase):
    @patch("django_auth.views.get_oidc_client")
    def test_login_redirects_to_the_provider(self, get_client):
        client = Mock()
        client.authorize_redirect.return_value = HttpResponseRedirect(
            "https://auth.example/application/o/authorize/"
        )
        get_client.return_value = client

        response = self.client.get("/_auth/login?next=/private")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers["Location"],
            "https://auth.example/application/o/authorize/",
        )
        self.assertEqual(
            client.authorize_redirect.call_args.args[1],
            "http://testserver/_auth/callback",
        )

    @patch("django_auth.views.get_oidc_client")
    def test_callback_establishes_the_identity_session(self, get_client):
        client = Mock()
        client.authorize_access_token.return_value = {
            "expires_at": time() + 3600,
            "userinfo": {
                "sub": ADA.subject,
                "email": ADA.email,
                "name": ADA.name,
                "groups": list(ADA.roles),
            },
        }
        get_client.return_value = client
        session = self.client.session
        session["django_auth.next"] = "/private"
        session.save()

        response = self.client.get("/_auth/callback?code=code&state=state")

        self.assertRedirects(response, "/private", fetch_redirect_response=False)
        self.assertEqual(self.client.get("/private").content, b"user-123")

    @patch("django_auth.views.get_oidc_client")
    def test_callback_rejects_an_identity_without_a_subject(self, get_client):
        client = Mock()
        client.authorize_access_token.return_value = {
            "userinfo": {"email": "ada@example.com"}
        }
        get_client.return_value = client

        self.assertEqual(self.client.get("/_auth/callback").status_code, 400)

    @patch("django_auth.views.get_oidc_client")
    def test_external_next_url_is_not_saved(self, get_client):
        client = Mock()
        client.authorize_redirect.return_value = HttpResponseRedirect(
            "https://auth.example/application/o/authorize/"
        )
        get_client.return_value = client

        self.client.get("/_auth/login?next=https://evil.example/")

        self.assertEqual(self.client.session["django_auth.next"], "/")
