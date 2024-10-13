# Flash OIDC Serverless Provider

**Flash OIDC Serverless Provider** is a lightweight and scalable OpenID Connect (OIDC) Provider built with a serverless architecture, leveraging Google Cloud's Datastore for efficient data management. This project is designed to offer a secure and flexible identity provider solution, ideal for modern cloud-native applications.

## Key Features:
- **Secure User Authentication**: Robust system for authenticating users with username and password credentials.
- **Standards-Compliant Token Handling**: Generates and manages access, refresh, and ID tokens in compliance with OAuth 2.0 and OpenID Connect standards.
- **Flexible Authorization Flows**: Supports multiple OAuth 2.0 grant types, including authorization code and password flows.
- **Comprehensive Endpoint Suite**: Offers essential endpoints for authorization, token exchange, user info retrieval, and OpenID Connect discovery.
- **Dynamic Client Management**: Provides API-based registration and management of OAuth clients.
- **Advanced Token Security**: Implements refresh token rotation and configurable expiration times for enhanced security.
- **Scalable Rate Limiting**: Configurable rate limiting system to protect against abuse and ensure fair resource allocation.
- **Detailed Audit Logging**: Comprehensive logging of authentication events and token operations for security and compliance.
- **Customizable Scope Management**: Flexible system for defining and managing access scopes for fine-grained authorization control.
- **CORS Support**: Built-in Cross-Origin Resource Sharing (CORS) support for integration with web applications.
- **Health Monitoring**: Includes a dedicated health check endpoint for system status monitoring.
- **Google Cloud Datastore Integration**: Utilizes Google Cloud Datastore for efficient and scalable data management.
- **FastAPI Framework**: Built on the modern, fast (high-performance) FastAPI web framework for Python.
- **OpenID Connect Discovery**: Provides a discovery mechanism for clients to automatically configure themselves.

## Use Cases:
- Identity provider for web and mobile applications.
- Secure user authentication for microservices.
- Serverless environments that require a lightweight OIDC provider.

## Getting Started:
1. Clone the repository.
2. Set up your Google Cloud project and enable the necessary APIs.
3. Follow the deployment guide to configure and deploy the service.

## Contributions:
Feel free to contribute by opening issues or submitting pull requests. We welcome feedback and suggestions to improve this project.

## Run on Google Cloud:

[![Run on Google Cloud](https://deploy.cloud.run/button.svg)](https://deploy.cloud.run/?git_repo=https://github.com/davideconsonni/flash-oidc-serverless-provider.git)


