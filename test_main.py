import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

# Importa il tuo modulo principale
from main import app, get_password_hash


class TestOpenIDProvider(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.test_user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "full_name": "Test User",
            "password": "testpassword123"
        }

        # Mock di Datastore
        self.datastore_patch = patch('google.cloud.datastore.Client')
        self.mock_datastore = self.datastore_patch.start()
        self.mock_client = Mock()
        self.mock_datastore.return_value = self.mock_client

        # Configura il mock per simulare un utente nel database
        mock_query = Mock()
        self.mock_client.query.return_value = mock_query
        mock_query.add_filter = Mock()
        mock_entity = Mock()
        mock_entity.items.return_value = {
            "username": self.test_user_data["username"],
            "email": self.test_user_data["email"],
            "full_name": self.test_user_data["full_name"],
            "hashed_password": get_password_hash(self.test_user_data["password"])
        }.items()
        mock_query.fetch.return_value = [mock_entity]

    def tearDown(self):
        self.datastore_patch.stop()

    def test_openid_configuration(self):
        response = self.client.get("/.well-known/openid-configuration")
        self.assertEqual(response.status_code, 200)
        config = response.json()
        self.assertEqual(config["token_endpoint"], "http://testserver/token")
        self.assertEqual(config["userinfo_endpoint"], "http://testserver/userinfo")

    def test_jwks(self):
        response = self.client.get("/jwks.json")
        self.assertEqual(response.status_code, 200)
        jwks = response.json()
        self.assertIn("keys", jwks)
        self.assertEqual(len(jwks["keys"]), 1)
        self.assertEqual(jwks["keys"][0]["alg"], "HS256")

    def test_token_endpoint_success(self):
        response = self.client.post(
            "/token",
            data={
                "username": self.test_user_data["username"],
                "password": self.test_user_data["password"],
                "grant_type": "password"
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        self.assertEqual(response.status_code, 200)
        token_data = response.json()
        self.assertIn("access_token", token_data)
        self.assertIn("refresh_token", token_data)
        self.assertEqual(token_data["token_type"], "bearer")

    def test_token_endpoint_invalid_credentials(self):
        response = self.client.post(
            "/token",
            data={
                "username": self.test_user_data["username"],
                "password": "wrongpassword",
                "grant_type": "password"
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        self.assertEqual(response.status_code, 401)

    def test_refresh_token(self):
        # Prima otteniamo un token valido
        token_response = self.client.post(
            "/token",
            data={
                "username": self.test_user_data["username"],
                "password": self.test_user_data["password"],
                "grant_type": "password"
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        refresh_token = token_response.json()["refresh_token"]

        # Ora testiamo il refresh
        response = self.client.post(
            "/refresh",
            json={"refresh_token": refresh_token}
        )
        self.assertEqual(response.status_code, 200)
        new_token_data = response.json()
        self.assertIn("access_token", new_token_data)
        self.assertIn("refresh_token", new_token_data)

    def test_userinfo_endpoint(self):
        # Prima otteniamo un token valido
        token_response = self.client.post(
            "/token",
            data={
                "username": self.test_user_data["username"],
                "password": self.test_user_data["password"],
                "grant_type": "password"
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        access_token = token_response.json()["access_token"]

        # Testiamo l'endpoint userinfo
        response = self.client.get(
            "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        self.assertEqual(response.status_code, 200)
        user_data = response.json()
        self.assertEqual(user_data["username"], self.test_user_data["username"])
        self.assertEqual(user_data["email"], self.test_user_data["email"])

    def test_userinfo_invalid_token(self):
        response = self.client.get(
            "/userinfo",
            headers={"Authorization": "Bearer invalid_token"}
        )
        self.assertEqual(response.status_code, 401)

    def test_error_handling(self):
        # Testiamo la gestione degli errori generici
        with patch('main.get_current_user', side_effect=Exception("Test error")):
            response = self.client.get(
                "/userinfo",
                headers={"Authorization": "Bearer dummy_token"}
            )
            self.assertEqual(response.status_code, 500)

if __name__ == '__main__':
    unittest.main()

