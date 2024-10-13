import random
from locust import HttpUser, task, between

class OpenIDConnectUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        self.username = "aaa"
        self.password = "aaa"
        self.client_id = "your_client_id"
        self.client_secret = "your_client_secret"
        self.access_token = None
        self.refresh_token = None

    @task(1)
    def login(self):
        response = self.client.post("/token", data={
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "openid profile email"
        })
        if response.status_code == 200:
            data = response.json()
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]

    @task(3)
    def get_user_info(self):
        if self.access_token:
            self.client.get("/userinfo", headers={"Authorization": f"Bearer {self.access_token}"})

    @task(1)
    def refresh_token(self):
        if self.refresh_token:
            response = self.client.post("/refresh", json={"refresh_token": self.refresh_token})
            if response.status_code == 200:
                data = response.json()
                self.access_token = data["access_token"]
                self.refresh_token = data["refresh_token"]

    @task(1)
    def health_check(self):
        self.client.get("/health")
