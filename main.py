import base64
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from datetime import timedelta
from functools import wraps
from typing import Dict, Any, Optional, List, Set
from urllib.parse import urlencode

from argon2 import PasswordHasher
from cachetools import TTLCache, cached
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Body, Form
from fastapi import Depends, HTTPException, status, Request
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import HTTPBasic
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.utils import get_authorization_scheme_param
from google.cloud import datastore
from google.cloud import storage
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field, field_validator, constr
from pythonjsonlogger import jsonlogger
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.templating import Jinja2Templates

# Configurazione
BUCKET_NAME = os.environ.get("BUCKET_NAME", "busysummer44-flash-oidc-serverless-provider")
PRIVATE_KEY_BLOB_NAME = os.environ.get("PRIVATE_KEY_BLOB_NAME", "rsa_private_key.pem")
PUBLIC_KEY_BLOB_NAME = os.environ.get("PUBLIC_KEY_BLOB_NAME", "rsa_public_key.pem")

ALGORITHM = os.environ.get("ALGORITHM", "RS256")
LIMITER_DEFAULT_LIMIT = os.environ.get("LIMITER_DEFAULT_LIMIT", "10000/second")

ENABLE_ADMIN_ENDPOINTS = os.environ.get("ENABLE_ADMIN_ENDPOINTS", str("False")).lower() in ("yes", "y", "true", "1", "ok")

# Configurazione degli scope e dei claim
DEFAULT_SCOPES = {"openid", "profile"}
SCOPE_CLAIMS_MAP = json.loads(os.environ.get("SCOPE_CLAIMS_MAP", '{"profile": ["disabled", "full_name"], "email": ["email"], "address": ["street_address", "locality", "region", "postal_code", "country"]}'))

SUPPORTED_CLAIMS = set(claim for claims in SCOPE_CLAIMS_MAP.values() for claim in claims)

# Aggiorna SUPPORTED_SCOPES per includere gli scope definiti nella configurazione
SUPPORTED_SCOPES = DEFAULT_SCOPES.union(set(SCOPE_CLAIMS_MAP.keys()))

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", 1))
ID_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ID_TOKEN_EXPIRE_MINUTES", 60))
ISSUER = os.environ.get("ISSUER", "http://127.0.0.1:8080")
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
    version="3.1.0",
    openapi_url="/openapi.json",
    docs_url="/docs",
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

# Password hashing
ph = PasswordHasher()

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={
        scope: (
            "OpenID scope" if scope == "openid" else
            f"Access to {', '.join(SCOPE_CLAIMS_MAP.get(scope, [scope]))} information"
        ) for scope in SUPPORTED_SCOPES
    }
)

# Creiamo una cache con un tempo di vita (TTL) di 1 ora e una dimensione massima di 100 elementi
keys_cache = TTLCache(maxsize=100, ttl=1) # 3600
user_cache = TTLCache(maxsize=1000, ttl=1)  # 300 Cache per 1000 utenti, TTL di 5 minuti
client_cache = TTLCache(maxsize=100, ttl=1)  # 3600 Cache per 100 client, TTL di 1 ora

# Configurazione logging
logging.basicConfig(level=logging.INFO)

class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        log_record['severity'] = record.levelname
        log_record['module'] = record.module

def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Rimuovi tutti gli handler esistenti
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Aggiungi un nuovo handler
    handler = logging.StreamHandler()

    if os.environ.get('GOOGLE_CLOUD_PROJECT'):
        # Formattatore JSON per GCP
        from pythonjsonlogger import jsonlogger
        formatter = jsonlogger.JsonFormatter('%(timestamp)s %(severity)s %(module)s %(message)s')
    else:
        # Formattatore leggibile per console locale
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

logger = setup_logging()

def log_audit_event(event_type: str, user: str, details: dict):
    timestamp = datetime.utcnow().isoformat()
    audit_entry = {
        "timestamp": timestamp,
        "event_type": event_type,
        "user": user,
        "details": details
    }

    if os.environ.get('GOOGLE_CLOUD_PROJECT'):
        # Log strutturato per GCP
        logger.info(audit_entry)
    else:
        # Log leggibile per console locale
        logger.info(f"AUDIT: {json.dumps(audit_entry, indent=2)}")

# --- Modelli Pydantic per la validazione ---

class User(BaseModel):
    username: constr(min_length=3, max_length=20) = Field(..., description="User's unique username")
    email: EmailStr = Field(..., description="User's email address")
    additional_claims: Dict[str, Any] = Field(default_factory=dict, description="Additional user claims")

class UserInDB(User):
    hashed_password: str = Field(..., description="Hashed password of the user")

    def verify_password(self, plain_password: str) -> bool:
        return verify_password(plain_password, self.hashed_password)

    class Config:
        exclude = {"hashed_password"}

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
    allowed_scopes: List[str] = Field(..., description="List of allowed scopes for this client")

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

class DynamicUserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    email: EmailStr
    password: str = Field(..., min_length=8)
    additional_claims: Dict[str, Any] = Field(default_factory=dict)

    @field_validator('additional_claims')
    @classmethod
    def validate_additional_claims(cls, v):
        for claim in v.keys():
            if claim not in SUPPORTED_CLAIMS:
                raise ValueError(f"Unsupported claim: {claim}")
        return v

# --- Fine Modelli Pydantic ---


# --- Funzioni di utilità ---

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


@cached(keys_cache)
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
    expiration_time = datetime.now(timezone.utc) + timedelta(minutes=ID_TOKEN_EXPIRE_MINUTES)
    auth_entity.update({
        "token": auth_token,
        "user_id": user_id,
        "expires": expiration_time,
        "_ttl": expiration_time  # This property will be used for automatic deletion
    })
    datastore_client.put(auth_entity)
    return auth_token

def verify_authorization_code(code: str, client_id: str, redirect_uri: str) -> Optional[dict]:
    query = datastore_client.query(kind="AuthorizationCode")
    query.add_filter("code", "=", code)
    query.add_filter("client_id", "=", client_id)
    query.add_filter("redirect_uri", "=", redirect_uri)
    results = list(query.fetch(limit=1))

    if not results or results[0]["expires"] < datetime.now(timezone.utc):
        return None

    auth_code = results[0]

    # Elimina il codice di autorizzazione utilizzato
    datastore_client.delete(results[0].key)

    return auth_code

def verify_auth_token(auth_token: str) -> Optional[str]:
    query = datastore_client.query(kind="AuthToken")
    query.add_filter("token", "=", auth_token)
    results = list(query.fetch(limit=1))

    if not results:
        return None

    token_entity = results[0]

    # Assicurati che il datetime memorizzato sia UTC e offset-aware
    stored_expiry = token_entity["expires"].replace(tzinfo=timezone.utc)
    current_time = datetime.now(timezone.utc)

    if stored_expiry <= current_time:
        # Token is expired, delete it and return None
        datastore_client.delete(token_entity.key)
        return None

    return token_entity["user_id"]

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)

def create_id_token(user: UserInDB, client_id: str, scopes: set, nonce: Optional[str] = None) -> str:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=ID_TOKEN_EXPIRE_MINUTES)

    payload = {
        "iss": ISSUER,
        "sub": user.username,
        "aud": client_id,
        "exp": expires,
        "iat": now,
        "auth_time": now,
    }

    if nonce:
        payload["nonce"] = nonce

    # Aggiungi i claim in base agli scope richiesti
    for scope in scopes:
        if scope in SCOPE_CLAIMS_MAP:
            for claim in SCOPE_CLAIMS_MAP[scope]:
                if hasattr(user, claim):
                    payload[claim] = getattr(user, claim)

    json_payload = json.dumps(payload, cls=DateTimeEncoder)
    return jwt.encode(json.loads(json_payload), private_pem, algorithm=ALGORITHM)


@cached(user_cache)
def get_user(username: str) -> Optional[UserInDB]:
    user_key = datastore_client.key("User", username)
    user_data = datastore_client.get(user_key)

    if not user_data:
        return None

    # Ensure username is explicitly included in the user data
    user_data["username"] = username

    additional_claims = {k: v for k, v in user_data.items() if k in SUPPORTED_CLAIMS or k in User.__fields__ or k == "hashed_password"}

    return UserInDB(**user_data, additional_claims=additional_claims)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return ph.verify(hashed_password, plain_password)
    except:
        return False

def get_password_hash(password: str) -> str:
    return ph.hash(password)

def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    user = get_user(username)
    if not user:
        log_audit_event("user_authentication_failed", username, {
            "reason": "User not found"
        })
        return None
    if not user.verify_password(password):
        log_audit_event("user_authentication_failed", username, {
            "reason": "Invalid password"
        })
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

def create_refresh_token(username: str, scopes: set, client_id: str) -> str:
    expires = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    # Converti la chiave privata in formato PEM
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    refresh_token = jwt.encode(
        {"sub": username, "type": "refresh", "exp": expires, "scopes": list(scopes), "client_id": client_id},
        pem,
        algorithm=ALGORITHM
    )

    # Salva il refresh token nel Datastore
    entity = datastore.Entity(key=datastore_client.key("RefreshToken"))
    entity.update({
        "token": refresh_token,
        "username": username,
        "expires": expires,
        "scopes": list(scopes),
        "client_id": client_id
    })
    datastore_client.put(entity)

    return refresh_token

def store_client(client_data: ClientRegistrationData):
    hashed_client_secret = get_password_hash(client_data.client_secret)

    entity = datastore.Entity(key=datastore_client.key("Client", client_data.client_id))
    entity.update({
        "client_id": client_data.client_id,
        "hashed_client_secret": hashed_client_secret,
        "allowed_scopes": client_data.allowed_scopes
    })
    datastore_client.put(entity)

    # Invalida la cache per questo client_id
    client_cache.pop(client_data.client_id, None)


@cached(client_cache)
def get_client(client_id: str):
    client_key = datastore_client.key("Client", client_id)
    return datastore_client.get(client_key)

def verify_client(client_id: str, client_secret: str, requested_scopes: Set[str]) -> bool:
    if not client_id or not client_secret:
        log_audit_event("client_verification_failed", "system", {
            "reason": "Missing client_id or client_secret"
        })
        return False

    client_data = get_client(client_id)

    if not client_data:
        log_audit_event("client_verification_failed", "system", {
            "reason": "Client not found",
            "client_id": client_id
        })
        return False

    if not verify_password(client_secret, client_data["hashed_client_secret"]):
        log_audit_event("client_verification_failed", "system", {
            "reason": "Invalid client secret",
            "client_id": client_id
        })
        return False

    allowed_scopes = set(client_data.get("allowed_scopes", []))
    if not requested_scopes.issubset(allowed_scopes):
        log_audit_event("client_verification_failed", "system", {
            "reason": "Requested scopes not allowed",
            "client_id": client_id,
            "requested_scopes": list(requested_scopes),
            "allowed_scopes": list(allowed_scopes)
        })
        return False

    return True

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

# --- Fine Funzioni di utilità ---


# --- Endpoints ---

def admin_endpoint(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        if not ENABLE_ADMIN_ENDPOINTS:
            raise HTTPException(status_code=404, detail="Endpoint not found")
        return await func(*args, **kwargs)
    return wrapper

@app.post("/token", response_model=TokenResponse, tags=["authentication"])
@limiter.limit(LIMITER_DEFAULT_LIMIT)
async def login_for_access_token(
        request: Request,
        grant_type: str = Form(...),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
        code: Optional[str] = Form(None),
        redirect_uri: Optional[str] = Form(None),
        username: Optional[str] = Form(None),
        password: Optional[str] = Form(None),
        scope: Optional[str] = Form(None)
):
    # Gestione dell'Authorization header per le credenziali del client
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

    requested_scopes = set(scope.split() if scope else ["openid"])

    # Verifica le credenziali del client e gli scope richiesti
    if not verify_client(client_id, client_secret, requested_scopes):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials or requested scopes",
        )

    if grant_type == "authorization_code":
        if not code or not redirect_uri:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing code or redirect_uri for authorization_code grant type",
            )
        # Valida il codice di autorizzazione
        auth_code = verify_authorization_code(code, client_id, redirect_uri)
        if not auth_code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired authorization code",
            )
        user = get_user(auth_code["user_id"])
        scopes = set(auth_code.get("scope", "openid").split())
        nonce = auth_code.get("nonce")
    elif grant_type == "password":
        if not username or not password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing username or password for password grant type",
            )
        user = authenticate_user(username, password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        scopes = set(scope.split() if scope else ["openid"])
        nonce = None
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported grant_type",
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
    refresh_token = create_refresh_token(user.username, valid_scopes, client_id)
    id_token = create_id_token(user, client_id, valid_scopes, nonce)

    log_audit_event("token_issued", user.username, {
        "client_id": client_id,
        "grant_type": grant_type,
        "scopes": list(valid_scopes)
    })

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "id_token": id_token,
    }


@app.post("/register", tags=["admin"])
@limiter.limit(LIMITER_DEFAULT_LIMIT)
@admin_endpoint
async def register_client(request: Request, client_data: ClientRegistrationData = Body(...)):
    """
    Register a new OAuth2 client.

    - **client_id**: The client's unique identifier
    - **client_secret**: The client's secret
    - **allowed_scopes**: List of allowed scopes for this client

    Returns the registered client_id.
    """
    # Verifica che gli scope richiesti siano validi
    invalid_scopes = set(client_data.allowed_scopes) - SUPPORTED_SCOPES
    if invalid_scopes:
        raise HTTPException(status_code=400, detail=f"Invalid scopes: {', '.join(invalid_scopes)}")

    # Store the client credentials securely
    store_client(client_data)

    log_audit_event("client_registered", "system", {
        "client_id": client_data.client_id,
        "allowed_scopes": client_data.allowed_scopes,
        "ip": request.client.host,
        "user_agent": request.headers.get("User-Agent")
    })

    return {"client_id": client_data.client_id, "allowed_scopes": client_data.allowed_scopes}


@app.post("/refresh", tags=["authentication"])
@limiter.limit(LIMITER_DEFAULT_LIMIT)
async def refresh_token(request: Request, refresh_token_data: RefreshToken = Body(...)):
    """
    Use a refresh token to get a new access token.

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
        query.add_filter(filter=("token", "=", refresh_token_data.refresh_token))
        query.add_filter(filter=("username", "=", username))
        results = list(query.fetch(limit=1))

        if not results:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found",
            )

        refresh_token_entity = results[0]

        # Recupera gli scope e il client_id originali
        original_scopes = set(refresh_token_entity.get("scopes", ["openid"]))
        client_id = refresh_token_entity.get("client_id")

        if not client_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Client ID not found in refresh token",
            )

        # Genera nuovi token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = create_access_token(
            data={"sub": username, "scope": " ".join(original_scopes)},
            expires_delta=access_token_expires
        )
        new_refresh_token = create_refresh_token(username, original_scopes, client_id)

        # Elimina il vecchio refresh token
        datastore_client.delete(results[0].key)
        log_audit_event("refresh_token_invalidated", username, {
            "client_id": client_id,
            "ip": request.client.host
        })

        # Calculate token expiration times in seconds
        access_token_expires_in_seconds = ACCESS_TOKEN_EXPIRE_MINUTES * 60

        # Recupera l'utente per generare l'id_token
        user = get_user(username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        # Genera un nuovo id_token
        id_token = create_id_token(user, client_id, original_scopes)

        log_audit_event("token_refreshed", username, {
            "username": username,
            "scopes": list(original_scopes),
            "client_id": client_id
        })

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "expires_in": access_token_expires_in_seconds,
            "id_token": id_token,
            "scope": " ".join(original_scopes)
        }

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )


@app.get("/userinfo", tags=["authentication"])
@limiter.limit(LIMITER_DEFAULT_LIMIT)
async def read_users_me(request: Request, current_user: User = Depends(get_current_user), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])
        scopes = set(payload.get("scope", "").split())
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_info = {"sub": current_user.username}

    for scope in scopes:
        if scope in SCOPE_CLAIMS_MAP:
            for claim in SCOPE_CLAIMS_MAP[scope]:
                if claim in current_user.additional_claims:
                    user_info[claim] = current_user.additional_claims[claim]
                elif hasattr(current_user, claim):
                    user_info[claim] = getattr(current_user, claim)

    # # Aggiungi tutti i claims aggiuntivi
    # user_info.update(current_user.additional_claims)

    return user_info

@app.get("/.well-known/openid-configuration", tags=["authentication"])
@limiter.limit(LIMITER_DEFAULT_LIMIT)
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
        "introspection_endpoint": f"{base_url}/introspect",
        "jwks_uri": f"{base_url}/jwks.json",
        "response_types_supported": ["code", "id_token", "id_token token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [ALGORITHM],
        "scopes_supported": list(SUPPORTED_SCOPES),
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce"] + list(SUPPORTED_CLAIMS)
    }

@app.get("/jwks.json", tags=["authentication"])
@limiter.limit(LIMITER_DEFAULT_LIMIT)
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


@app.post("/introspect", tags=["authentication"])
@limiter.limit(LIMITER_DEFAULT_LIMIT)
async def introspect_token(
        request: Request,
        token: str = Form(...),
        token_type_hint: Optional[str] = Form(None),
        client_id: str = Form(...),
        client_secret: str = Form(...),
):
    """
    Introspect a token.

    This endpoint allows clients to query the authorization server to determine the state of an
    access token or refresh token and to determine meta-information about the token.
    """
    # Verify client credentials
    if not verify_client(client_id, client_secret, set()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        )

    try:
        # Decode the token without verifying to get the 'typ' claim
        unverified_payload = jwt.decode(token, key="dummy_key", options={"verify_signature": False})
        token_type = unverified_payload.get("typ", "access_token")

        # Now decode and verify the token
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])

        # Check if token is expired
        if datetime.fromtimestamp(payload['exp']) < datetime.utcnow():
            return {"active": False}

        # For refresh tokens, check if they exist in the database
        if token_type == "refresh_token":
            query = datastore_client.query(kind="RefreshToken")
            query.add_filter("token", "=", token)
            if not list(query.fetch(limit=1)):
                return {"active": False}

        # Token is valid
        response = {
            "active": True,
            "scope": payload.get("scope", ""),
            "client_id": payload.get("aud"),
            "username": payload.get("sub"),
            "token_type": token_type,
            "exp": payload["exp"],
            "iat": payload.get("iat"),
            "nbf": payload.get("nbf"),
            "sub": payload["sub"],
            "aud": payload.get("aud"),
            "iss": payload.get("iss"),
            "jti": payload.get("jti"),
        }

        # Remove None values
        return {k: v for k, v in response.items() if v is not None}

    except JWTError:
        return {"active": False}

    except Exception as e:
        logger.error(f"Error during token introspection: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid token")

@app.get("/authorize", tags=["authentication"])
@limiter.limit(LIMITER_DEFAULT_LIMIT)
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

    # Verifica client_id e scope
    client = datastore_client.get(datastore_client.key("Client", client_id))
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    requested_scopes = set(scope.split())
    allowed_scopes = set(client.get("allowed_scopes", []))
    if not requested_scopes.issubset(allowed_scopes):
        raise HTTPException(status_code=400, detail="Requested scopes not allowed for this client")

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
    log_audit_event("authorization_code_generated", user_id, {
        "client_id": client_id,
        "scope": " ".join(valid_scopes),
        "response_type": response_type,
        "ip": request.client.host
    })

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


@app.post("/users", response_model=User, tags=["admin"])
@limiter.limit(LIMITER_DEFAULT_LIMIT)
@admin_endpoint
async def create_user(user: DynamicUserCreate, request: Request):
    """
    Create a new user with dynamic fields based on supported claims.

    - **username**: The user's unique username (3-20 characters)
    - **email**: The user's email address
    - **password**: The user's password (minimum 8 characters)
    - **additional_claims**: Additional user claims based on supported scopes

    Returns the created user object (excluding the password).
    """
    # Check if username already exists
    existing_user = get_user(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Check if email already exists
    query = datastore_client.query(kind="User")
    query.add_filter("email", "=", user.email)
    if list(query.fetch(limit=1)):
        raise HTTPException(status_code=400, detail="Email already registered")

    # Hash the password
    hashed_password = get_password_hash(user.password)

    # Create new user entity
    new_user = datastore.Entity(key=datastore_client.key("User", user.username))
    new_user.update({
        "username": user.username,
        "email": user.email,
        "hashed_password": hashed_password,
        "disabled": False
    })

    # Add additional claims
    for claim, value in user.additional_claims.items():
        new_user[claim] = value

    # Save the new user
    datastore_client.put(new_user)

    # Clear the user cache for this username
    user_cache.pop(user.username, None)

    # Log the event
    log_audit_event("user_created", user.username, {
        "ip": request.client.host,
        "user_agent": request.headers.get("User-Agent")
    })

    # Create a User object from the new_user entity
    created_user = User(
        username=new_user["username"],
        email=new_user["email"],
        additional_claims={k: v for k, v in new_user.items() if k not in ["username", "email", "hashed_password", "disabled"]}
    )

    return created_user

@app.get("/login", response_class=HTMLResponse)
@limiter.limit(LIMITER_DEFAULT_LIMIT)
async def login(request: Request):
    """
    Display the login page.

    This endpoint returns an HTML page with a login form for user authentication.
    """
    return templates.TemplateResponse("login.html", {"request": request, "next": request.query_params.get("next")})

@app.post("/login", tags=["authentication"])
@limiter.limit(LIMITER_DEFAULT_LIMIT)
async def login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        redirect_uri: str = Form(None)
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
        log_audit_event("login_failed", username, {
            "ip": request.client.host,
            "user_agent": request.headers.get("User-Agent")
        })
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Incorrect username or password", "redirect_uri": redirect_uri}
        )

    auth_token = create_auth_token(user.username)
    log_audit_event("login_successful", user.username, {
        "ip": request.client.host,
        "user_agent": request.headers.get("User-Agent")
    })
    if redirect_uri:
        return RedirectResponse(f"{redirect_uri}?auth_token={auth_token}", status_code=303)
    return RedirectResponse(f"/?auth_token={auth_token}", status_code=303)

@app.get("/health", tags=["monitoring"])
@limiter.limit(LIMITER_DEFAULT_LIMIT)
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
    log_audit_event("unhandled_exception", "system", {
        "error": str(exc),
        "path": request.url.path,
        "method": request.method,
        "ip": request.client.host
    })
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

# --- Fine Endpoins ---

# ---  Inizializzazione delle chiavi ---

private_key, public_key = get_keys_from_storage()

if not private_key or not public_key:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    save_keys_to_storage(private_key, public_key)

# Converti la chiave privata in formato PEM
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Converti la chiave pubblica in formato PEM
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

kid = base64.urlsafe_b64encode(public_pem).decode('utf-8')[:8]

# --- Fine Inizializzazione Chiavi ---


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
