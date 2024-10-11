import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request, Response, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from google.cloud import datastore
from jose import JWTError, jwt
from passlib.context import CryptContext

# Configurazione
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1
REFRESH_TOKEN_EXPIRE_DAYS = 1

# Custom namespace for OpenID users
NAMESPACE = "openid_users"

# Initialize Datastore client with the custom namespace
datastore_client = datastore.Client(namespace=NAMESPACE)

security = HTTPBasic()

# Inizializzazione FastAPI
app = FastAPI(title="OpenID Connect Provider")

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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Custom Python classes
class User:
    def __init__(self, username: str, email: str, full_name: Optional[str] = None, disabled: Optional[bool] = None):
        self.username = username
        self.email = email
        self.full_name = full_name
        self.disabled = disabled

class UserInDB(User):
    def __init__(self, username: str, hashed_password: str, email: str, full_name: Optional[str] = None, disabled: Optional[bool] = None):
        super().__init__(username, email, full_name, disabled)
        self.hashed_password = hashed_password

class Token:
    def __init__(self, access_token: str, token_type: str, refresh_token: str):
        self.access_token = access_token
        self.token_type = token_type
        self.refresh_token = refresh_token

class TokenData:
    def __init__(self, username: Optional[str] = None):
        self.username = username

class RefreshToken:
    def __init__(self, refresh_token: str):
        self.refresh_token = refresh_token

# Funzioni di utilità
def get_user(username: str) -> Optional[UserInDB]:
    user_key = datastore_client.key("User", username)
    user_data = datastore_client.get(user_key)

    if not user_data:
        return None

    # Ensure username is explicitly included in the user data
    user_data["username"] = username

    return UserInDB(username=user_data["username"], hashed_password=user_data["hashed_password"], email=user_data["email"], full_name=user_data.get("full_name"), disabled=user_data.get("disabled"))

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
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(username: str) -> str:
    expires = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = create_access_token(
        data={"sub": username, "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
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

def store_client(client_id: str, client_secret: str):
    # Hash the client_secret before storing
    hashed_client_secret = get_password_hash(client_secret)

    entity = datastore.Entity(key=datastore_client.key("Client", client_id))
    entity.update({
        "client_id": client_id,
        "hashed_client_secret": hashed_client_secret,
    })
    datastore_client.put(entity)

def verify_client(client_id: str, client_secret: str) -> bool:
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
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
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
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # Verifica le credenziali del client
    if not verify_client(form_data.client_id, form_data.client_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        )

    # Autentica l'utente
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate tokens as usual
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    refresh_token = create_refresh_token(user.username)
    access_token_expires_in_seconds = ACCESS_TOKEN_EXPIRE_MINUTES * 60

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires": access_token_expires_in_seconds,
    }


@app.post("/register")
async def register_client(data: dict = Body(...)):
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")

    if not client_id or not client_secret:
        raise HTTPException(status_code=400, detail="client_id and client_secret are required")

    # Store the client credentials securely
    store_client(client_id, client_secret)

    return {"client_id": client_id}


@app.post("/refresh")
async def refresh_token(refresh_token: dict):
    try:
        payload = jwt.decode(refresh_token['refresh_token'], SECRET_KEY, algorithms=[ALGORITHM])
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
        query.add_filter("token", "=", refresh_token['refresh_token'])
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



@app.get("/userinfo")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user.__dict__

@app.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request):
    base_url = str(request.base_url).rstrip('/')
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "userinfo_endpoint": f"{base_url}/userinfo",
        "jwks_uri": f"{base_url}/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "claims_supported": ["sub", "iss", "name", "email"]
    }

@app.get("/jwks.json")
async def jwks():
    return {
        "keys": [
            {
                "kty": "oct",
                "use": "sig",
                "kid": "1",
                "k": SECRET_KEY,
                "alg": "HS256"
            }
        ]
    }

# Gestione errori
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return Response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content="An internal server error occurred."
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
