from google.cloud import datastore
from argon2 import PasswordHasher
import os
import logging

# Ensure you have set the GOOGLE_APPLICATION_CREDENTIALS environment variable
# to the path of your service account key JSON file

# Custom namespace for OpenID users
NAMESPACE = "openid_users"

# Initialize Datastore client with the custom namespace
datastore_client = datastore.Client(namespace=NAMESPACE)

# Initialize Argon2 PasswordHasher
ph = PasswordHasher()

def create_user(username, email, password, full_name=None):
    user_key = datastore_client.key("User", username)

    # Check if user already exists
    if datastore_client.get(user_key):
        print(f"User {username} already exists in namespace {NAMESPACE}.")
        return

    # Create new user entity with the custom key
    user_entity = datastore.Entity(key=user_key)
    user_entity.update({
        "username": username,  # Make sure this is included
        "email": email,
        "hashed_password": ph.hash(password),
        "full_name": full_name,
        "disabled": False
    })

    # Save user to Datastore in the custom namespace
    datastore_client.put(user_entity)
    print(f"User {username} created successfully in namespace {NAMESPACE}.")

if __name__ == "__main__":
    username = input("Enter username: ")
    email = input("Enter email: ")
    password = input("Enter password: ")
    full_name = input("Enter full name (optional): ")

    create_user(username, email, password, full_name)
