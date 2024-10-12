import logging
import base64
import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Body, Form
from fastapi import Depends, HTTPException, status, Request
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import HTTPBasic
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.security.utils import get_authorization_scheme_param
from google.cloud import datastore
from google.cloud import storage
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, constr, EmailStr, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.templating import Jinja2Templates

# Configurazione
BUCKET_NAME = os.environ.get("BUCKET_NAME", "busysummer44-flash-oidc-serverless-provider")
PRIVATE_KEY_BLOB_NAME = os.environ.get("PRIVATE_KEY_BLOB_NAME", "rsa_private_key.pem")
PUBLIC_KEY_BLOB_NAME = os.environ.get("PUBLIC_KEY_BLOB_NAME", "rsa_public_key.pem")

ALGORITHM = os.environ.get("ALGORITHM", "RS256")
SUPPORTED_SCOPES = {"openid", "profile", "email"}

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", 1))
ID_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ID_TOKEN_EXPIRE_MINUTES", 60))
ISSUER = os.environ.get("ISSUER", "https://flash-oidc-serverless-provider.com")
BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8080")

# Custom namespace for OpenID users
NAMESPACE = os.environ.get("NAMESPACE", "openid_users")

# Initialize Datastore client with the custom namespace
datastore_client = datastore.Client(namespace=NAMESPACE)

security = HTTPBasic()

# Inizializza il client di Storage
storage_client = storage.Client()
bucket = storage_client.bucket(BUCKET_NAME)


# Inizializzazione FastAPI
def get_remote_address(request: Request):
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0]
    return request.client.host

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="OpenID Connect Provider API",
    description="API per la gestione dell'autenticazione e autorizzazione OpenID Connect",
    version="1.0.0",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    servers=[
        {"url": BASE_URL, "description": "Current server"},
    ]
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Initialize Jinja2 templates
templates = Jinja2Templates(directory="templates")

# Configurazione CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In produzione, specificare i domini consentiti
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configurazione logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={
        "openid": "OpenID scope",
        "profile": "Access to user profile information",
        "email": "Access to user email"
    }
)

# --- Modelli Pydantic per la validazione ---
class User(BaseModel):
    username: constr(min_length=3, max_length=20) = Field(..., description="User's unique username")
    email: EmailStr = Field(..., description="User's email address")
    full_name: Optional[str] = Field(None, description="User's full name")
    disabled: Optional[bool] = Field(False, description="Whether the user account is disabled")

class UserInDB(User):
    hashed_password: str = Field(..., description="Hashed password of the user")

class Token(BaseModel):
    access_token: str = Field(..., description="The access token for API requests")
    token_type: str = Field(..., description="The type of token, typically 'bearer'")
    refresh_token: str = Field(..., description="Token used to obtain a new access token")

class TokenData(BaseModel):
    username: Optional[str] = Field(None, description="Username extracted from the token")

class RefreshToken(BaseModel):
    refresh_token: str = Field(..., description="The refresh token to exchange for a new access token")

class ClientRegistrationData(BaseModel):
    client_id: str = Field(..., description="The client's unique identifier")
    client_secret: str = Field(..., description="The client's secret")

class AuthorizationRequest(BaseModel):
    response_type: str = Field(..., description="The desired response type ('code', 'id_token', or 'id_token token')")
    client_id: str = Field(..., description="The client's unique identifier")
    redirect_uri: str = Field(..., description="The URI to redirect to after authorization")
    scope: str = Field(..., description="The requested scopes, space-separated")
    state: str = Field(..., description="A value used to maintain state between the request and callback")


class TokenResponse(BaseModel):
    access_token: str = Field(..., description="The access token for API requests")
    token_type: str = Field(..., description="The type of token, typically 'bearer'")
    refresh_token: str = Field(..., description="Token used to obtain a new access token")
    expires_in: int = Field(..., description="Number of seconds until the access token expires")
    id_token: str = Field(..., description="OpenID Connect ID Token")

# --- Fine Modelli Pydantic ---

# Funzioni di utilità

# Funzione per salvare le chiavi nel Datastore
def save_keys_to_storage(private_key, public_key):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Salva la chiave privata
    private_blob = bucket.blob(PRIVATE_KEY_BLOB_NAME)
    private_blob.upload_from_string(private_pem)

    # Salva la chiave pubblica
    public_blob = bucket.blob(PUBLIC_KEY_BLOB_NAME)
    public_blob.upload_from_string(public_pem)


def get_keys_from_storage():
    try:
        # Recupera la chiave privata
        private_blob = bucket.blob(PRIVATE_KEY_BLOB_NAME)
        private_pem = private_blob.download_as_bytes()

        # Recupera la chiave pubblica
        public_blob = bucket.blob(PUBLIC_KEY_BLOB_NAME)
        public_pem = public_blob.download_as_bytes()

        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None
        )
        public_key = serialization.load_pem_public_key(public_pem)

        return private_key, public_key
    except Exception as e:
        print(f"Errore nel recupero delle chiavi: {e}")
        return None, None



def create_auth_token(user_id: str) -> str:
    auth_token = secrets.token_urlsafe(32)
    auth_entity = datastore.Entity(key=datastore_client.key("AuthToken"))
    expiration_time = datetime.utcnow() + timedelta(minutes=ID_TOKEN_EXPIRE_MINUTES)
    auth_entity.update({
        "token": auth_token,
        "user_id": user_id,
        "expires": expiration_time,
        "_ttl": expiration_time  # This property will be used for automatic deletion
    })
    datastore_client.put(auth_entity)
    return auth_token


def verify_auth_token(auth_token: str) -> Optional[str]:
    query = datastore_client.query(kind="AuthToken")
    query.add_filter("token", "=", auth_token)
    results = list(query.fetch(limit=1))

    if not results:
        return None

    token_entity = results[0]

    if token_entity["expires"] <= datetime.utcnow():
        # Token is expired, delete it and return None
        datastore_client.delete(token_entity.key)
        return None

    return token_entity["user_id"]

def create_id_token(user: UserInDB, client_id: str, scopes: set, nonce: Optional[str] = None, auth_time: Optional[float] = None) -> str:
    now = datetime.utcnow()
    expires = now + timedelta(minutes=ID_TOKEN_EXPIRE_MINUTES)

    payload = {
        "iss": ISSUER,
        "sub": user.username,
        "aud": client_id,
        "exp": expires,
        "iat": now,
        "auth_time": auth_time or now.timestamp(),
    }

    if nonce:
        payload["nonce"] = nonce

    if "email" in scopes and user.email:
        payload["email"] = user.email

    if "profile" in scopes:
        if user.full_name:
            payload["name"] = user.full_name
        # Aggiungi altri campi del profilo se disponibili

    # Converti la chiave privata in formato PEM
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    return jwt.encode(payload, pem, algorithm=ALGORITHM)

def get_user(username: str) -> Optional[UserInDB]:
    user_key = datastore_client.key("User", username)
    user_data = datastore_client.get(user_key)

    if not user_data:
        return None

    # Ensure username is explicitly included in the user data
    user_data["username"] = username

    return UserInDB(**user_data)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})

    # Converti la chiave privata in formato PEM
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    encoded_jwt = jwt.encode(to_encode, pem, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(username: str) -> str:
    expires = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    # Converti la chiave privata in formato PEM
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    refresh_token = jwt.encode(
        {"sub": username, "type": "refresh", "exp": expires},
        pem,
        algorithm=ALGORITHM
    )

    # Salva il refresh token nel Datastore
    entity = datastore.Entity(key=datastore_client.key("RefreshToken"))
    entity.update({
        "token": refresh_token,
        "username": username,
        "expires": expires
    })
    datastore_client.put(entity)

    return refresh_token

def store_client(client_data: ClientRegistrationData):
    # Hash the client_secret before storing
    hashed_client_secret = get_password_hash(client_data.client_secret)

    entity = datastore.Entity(key=datastore_client.key("Client", client_data.client_id))
    entity.update({
        "client_id": client_data.client_id,
        "hashed_client_secret": hashed_client_secret,
    })
    datastore_client.put(entity)

def verify_client(client_id: str, client_secret: str) -> bool:
    if not client_id or not client_secret:
        return False

    # Fetch client details from Datastore
    client_key = datastore_client.key("Client", client_id)
    client_data = datastore_client.get(client_key)

    if not client_data:
        return False

    # Verify the provided client_secret
    return verify_password(client_secret, client_data["hashed_client_secret"])

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


# Endpoints
@app.post("/token", response_model=TokenResponse, tags=["Authentication"])
@limiter.limit("200/minute")
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 compatible token login, get an access token for future requests.
    """
    # Gestione dell'Authorization header per le credenziali del client
    client_id = None
    client_secret = None
    auth_header = request.headers.get("Authorization")
    if auth_header:
        scheme, param = get_authorization_scheme_param(auth_header)
        if scheme.lower() == "basic":
            try:
                decoded = base64.b64decode(param).decode("ascii")
                client_id, client_secret = decoded.split(":")
            except:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials",
                    headers={"WWW-Authenticate": "Basic"},
                )
    else:
        # Se non c'è l'Authorization header, usa i dati del form
        client_id = form_data.client_id
        client_secret = form_data.client_secret

    # Verifica le credenziali del client
    if not verify_client(client_id, client_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        )

    # Controlla se questa è una concessione del codice di autorizzazione
    if form_data.grant_type == "authorization_code":
        # Valida il codice di autorizzazione
        query = datastore_client.query(kind="AuthorizationCode")
        query.add_filter("code", "=", form_data.code)
        query.add_filter("client_id", "=", client_id)
        results = list(query.fetch(limit=1))

        if not results or results[0]["expires"] < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired authorization code",
            )

        auth_code = results[0]
        user = get_user(auth_code["user_id"])
        nonce = auth_code.get("nonce")
        auth_time = auth_code.get("auth_time")
        scopes = set(auth_code.get("scope", "openid").split())

        # Elimina il codice di autorizzazione utilizzato
        datastore_client.delete(results[0].key)
    else:
        # Fallback alla concessione della password (come implementato prima)
        user = authenticate_user(form_data.username, form_data.password)
        nonce = None
        auth_time = datetime.utcnow().timestamp()
        scopes = set(form_data.scopes) if form_data.scopes else {"openid"}

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Filtra gli scope validi
    valid_scopes = scopes.intersection(SUPPORTED_SCOPES)
    if "openid" not in valid_scopes:
        valid_scopes.add("openid")

    # Genera i token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "scope": " ".join(valid_scopes)},
        expires_delta=access_token_expires
    )

    refresh_token = create_refresh_token(user.username)
    access_token_expires_in_seconds = ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # Genera l'ID Token
    id_token = create_id_token(user, client_id, valid_scopes, nonce, auth_time)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": access_token_expires_in_seconds,
        "id_token": id_token,
    }


@app.post("/register")
@limiter.limit("200/minute")
async def register_client(request: Request, client_data: ClientRegistrationData = Body(...)):
    """
    Register a new OAuth2 client.

    - **client_id**: The client's unique identifier
    - **client_secret**: The client's secret

    Returns the registered client_id.
    """
    # La validazione dei dati è già gestita da Pydantic grazie al modello 'ClientRegistrationData'

    # Store the client credentials securely
    store_client(client_data)

    return {"client_id": client_data.client_id}


@app.post("/refresh", tags=["Authentication"])
@limiter.limit("200/minute")
async def refresh_token(request: Request, refresh_token_data: RefreshToken = Body(...)):
    """
    Use a refresh token to obtain a new access token.

    - **refresh_token**: The refresh token obtained during the initial token request

    Returns a new set of tokens including a fresh access_token.
    """
    try:
        payload = jwt.decode(refresh_token_data.refresh_token, public_key, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        username = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        # Verifica nel Datastore
        query = datastore_client.query(kind="RefreshToken")
        query.add_filter("token", "=", refresh_token_data.refresh_token)
        query.add_filter("username", "=", username)
        results = list(query.fetch(limit=1))

        if not results:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found",
            )

        # Genera nuovi token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = create_access_token(
            data={"sub": username}, expires_delta=access_token_expires
        )
        new_refresh_token = create_refresh_token(username)

        # Elimina il vecchio refresh token
        datastore_client.delete(results[0].key)

        # Calculate token expiration times in seconds
        access_token_expires_in_seconds = ACCESS_TOKEN_EXPIRE_MINUTES * 60

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "expires": access_token_expires_in_seconds,
        }

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )



@app.get("/userinfo", tags=["Authentication"])
@limiter.limit("200/minute")
async def read_users_me(request: Request, current_user: User = Depends(get_current_user), token: str = Depends(oauth2_scheme)):
    """
    Get information about the currently authenticated user.

    This endpoint requires a valid access token and returns user information based on the granted scopes.
    """
    try:
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])
        scopes = set(payload.get("scope", "").split())
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_info = {"sub": current_user.username}

    if "email" in scopes:
        user_info["email"] = current_user.email

    if "profile" in scopes:
        if current_user.full_name:
            user_info["name"] = current_user.full_name
        # Aggiungi altri campi del profilo se disponibili

    return user_info

@app.get("/.well-known/openid-configuration", tags=["Authentication"])
@limiter.limit("200/minute")
async def openid_configuration(request: Request):
    """
    Retrieve the OpenID Connect configuration information.

    This endpoint provides the necessary information for clients to interact with the OpenID Connect provider.
    """
    base_url = str(request.base_url).rstrip('/')
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "userinfo_endpoint": f"{base_url}/userinfo",
        "jwks_uri": f"{base_url}/jwks.json",
        "response_types_supported": ["code", "id_token", "id_token token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [ALGORITHM],
        "scopes_supported": list(SUPPORTED_SCOPES),
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "email"]
    }

@app.get("/jwks.json", tags=["Authentication"])
@limiter.limit("200/minute")
async def jwks(request: Request):
    """
    Retrieve the JSON Web Key Set (JWKS) used for token verification.

    This endpoint provides the public keys used to verify the signatures of issued tokens.
    """
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "kid": kid,
        "alg": ALGORITHM,
        "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes((public_key.public_numbers().n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
        "e": base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes((public_key.public_numbers().e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
    }
    return {"keys": [jwk]}

@app.get("/authorize", tags=["Authentication"])
@limiter.limit("200/minute")
async def authorize(
        request: Request,
        response_type: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: str,
        nonce: Optional[str] = None,
        auth_token: Optional[str] = None
):
    """
    Initiate the OAuth2 authorization flow.

    - **response_type**: The desired grant type ("code", "id_token", or "id_token token")
    - **client_id**: The client's ID
    - **redirect_uri**: The URI to redirect to after authorization
    - **scope**: The requested scopes, space-separated
    - **state**: A value used to maintain state between the request and callback
    - **nonce**: Optional nonce for ID Token requests
    - **auth_token**: Optional authentication token for already authenticated users

    This endpoint will either redirect to the login page or directly to the client with an authorization response.
    """
    # Valida la richiesta di autorizzazione
    if response_type not in ["code", "id_token", "id_token token"]:
        raise HTTPException(status_code=400, detail="Invalid response_type")

    # Verifica client_id
    client = datastore_client.get(datastore_client.key("Client", client_id))
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    if not auth_token:
        return RedirectResponse(f"/login?{urlencode(dict(request.query_params))}")

    user_id = verify_auth_token(auth_token)
    if not user_id:
        return RedirectResponse(f"/login?{urlencode(dict(request.query_params))}")

    user = get_user(user_id)

    # Valida e filtra gli scope
    requested_scopes = set(scope.split())
    valid_scopes = requested_scopes.intersection(SUPPORTED_SCOPES)
    if "openid" not in valid_scopes:
        raise HTTPException(status_code=400, detail="OpenID scope is required")

    # Genera il codice di autorizzazione
    auth_code = secrets.token_urlsafe(32)

    # Memorizza il codice di autorizzazione
    auth_code_entity = datastore.Entity(key=datastore_client.key("AuthorizationCode"))
    auth_code_entity.update({
        "code": auth_code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(valid_scopes),
        "user_id": user_id,
        "nonce": nonce,
        "auth_time": datetime.utcnow().timestamp(),
        "expires": datetime.utcnow() + timedelta(minutes=10)
    })
    datastore_client.put(auth_code_entity)

    # Prepara la risposta in base al response_type
    response_params = {"state": state}

    if response_type == "code":
        response_params["code"] = auth_code
    elif response_type in ["id_token", "id_token token"]:
        id_token = create_id_token(user, client_id, valid_scopes, nonce)
        response_params["id_token"] = id_token

        if response_type == "id_token token":
            access_token = create_access_token(data={"sub": user.username, "scope": " ".join(valid_scopes)})
            response_params["access_token"] = access_token
            response_params["token_type"] = "bearer"
            response_params["expires_in"] = ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # Reindirizza al client con i parametri appropriati
    redirect_uri = f"{redirect_uri}?{urlencode(response_params)}"
    return RedirectResponse(redirect_uri)

@app.get("/login", response_class=HTMLResponse)
@limiter.limit("200/minute")
async def login(request: Request):
    """
    Display the login page.

    This endpoint returns an HTML page with a login form for user authentication.
    """
    return templates.TemplateResponse("login.html", {"request": request, "next": request.query_params.get("next")})

@app.post("/login", tags=["Authentication"])
@limiter.limit("200/minute")
async def login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        next: str = Form(None)
):
    """
    Process the login form submission.

    - **username**: The user's username
    - **password**: The user's password
    - **next**: Optional URL to redirect to after successful login

    This endpoint authenticates the user and redirects to the appropriate page.
    """
    user = authenticate_user(username, password)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Incorrect username or password", "next": next}
        )

    auth_token = create_auth_token(user.username)

    if next:
        return RedirectResponse(f"{next}&auth_token={auth_token}", status_code=303)
    return RedirectResponse(f"/?auth_token={auth_token}", status_code=303)

@app.get("/health")
@limiter.limit("200/minute")
async def health_check(request: Request):
    """
    Perform a health check on the service.

    This endpoint verifies that the service is running and can respond to requests.
    It may also include additional checks for dependent services or resources.
    """
    try:
        # Qui puoi aggiungere controlli più approfonditi se necessario
        # Ad esempio, verifica la connessione al database, ecc.
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "healthy", "message": "Service is running"}
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "message": str(e)}
        )

@app.get("/", response_class=HTMLResponse)
async def root():
    """
    Root endpoint of the OpenID Connect Provider.

    This endpoint returns a simple HTML page with information about the service.
    """
    return """
    <html>
        <head>
            <title>OpenID Connect Provider</title>
        </head>
        <body>
            <h1>Welcome to the OpenID Connect Provider</h1>
            <p>This is the root endpoint of the OpenID Connect Provider API.</p>
            <p>For more information, please refer to the API documentation.</p>
        </body>
    </html>
    """

# Gestione errori
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return Response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content="An internal server error occurred."
    )

@app.exception_handler(RateLimitExceeded)
async def custom_rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Rate limit exceeded. Please try again later."}
    )

# ---  Inizializzazione delle chiavi ---
private_key, public_key = get_keys_from_storage()

if not private_key or not public_key:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    save_keys_to_storage(private_key, public_key)

# Il resto del codice rimane invariato
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

kid = base64.urlsafe_b64encode(pem).decode('utf-8')[:8]
# --- Inizializzazione delle chiavi ---

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
