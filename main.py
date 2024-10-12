import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Depends, Request, Response, status, Body, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import HTTPBasic, OAuth2PasswordRequestForm, OAuth2PasswordBearer
from google.cloud import datastore
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, constr, EmailStr
from starlette.templating import Jinja2Templates

# Configurazione
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 1
ID_TOKEN_EXPIRE_MINUTES = 60
ISSUER = "https://flash-oidc-serverless-provider.com"

# Custom namespace for OpenID users
NAMESPACE = "openid_users"

# Initialize Datastore client with the custom namespace
datastore_client = datastore.Client(namespace=NAMESPACE)

security = HTTPBasic()

# Inizializzazione FastAPI
app = FastAPI(title="OpenID Connect Provider")

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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Modelli Pydantic per la validazione ---
class User(BaseModel):
    username: constr(min_length=3, max_length=20)
    email: EmailStr
    full_name: Optional[str] = None
    disabled: Optional[bool] = False

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str

class TokenData(BaseModel):
    username: Optional[str] = None

class RefreshToken(BaseModel):
    refresh_token: str

class ClientRegistrationData(BaseModel):
    client_id: str
    client_secret: str

class AuthorizationRequest(BaseModel):
    response_type: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str
    expires_in: int
    id_token: str

# --- Fine Modelli Pydantic ---

# Funzioni di utilità
def create_auth_token(user_id: str) -> str:
    auth_token = secrets.token_urlsafe(32)
    auth_entity = datastore.Entity(key=datastore_client.key("AuthToken"))
    expiration_time = datetime.utcnow() + timedelta(minutes=15)
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

def create_id_token(user: UserInDB, client_id: str, nonce: Optional[str] = None, auth_time: Optional[float] = None) -> str:
    now = datetime.utcnow()
    expires = now + timedelta(minutes=ID_TOKEN_EXPIRE_MINUTES)

    payload = {
        "iss": ISSUER,
        "sub": user.username,  # Usiamo username come identificatore univoco
        "aud": client_id,
        "exp": expires,
        "iat": now,
        "auth_time": auth_time or now.timestamp(),
    }

    if nonce:
        payload["nonce"] = nonce

    # Aggiungi claims standard se disponibili
    if user.email:
        payload["email"] = user.email
    if user.full_name:
        payload["name"] = user.full_name

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

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
@app.post("/token", response_model=TokenResponse)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # Verifica le credenziali del client
    if not verify_client(form_data.client_id, form_data.client_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        )

    # Controlla se questa è una concessione del codice di autorizzazione
    if form_data.grant_type == "authorization_code":
        # Valida il codice di autorizzazione
        query = datastore_client.query(kind="AuthorizationCode")
        query.add_filter("code", "=", form_data.code)
        query.add_filter("client_id", "=", form_data.client_id)
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

        # Elimina il codice di autorizzazione utilizzato
        datastore_client.delete(results[0].key)
    else:
        # Fallback alla concessione della password (come implementato prima)
        user = authenticate_user(form_data.username, form_data.password)
        nonce = None
        auth_time = datetime.utcnow().timestamp()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Genera i token come al solito
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    refresh_token = create_refresh_token(user.username)
    access_token_expires_in_seconds = ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # Genera l'ID Token
    id_token = create_id_token(user, form_data.client_id, nonce, auth_time)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": access_token_expires_in_seconds,
        "id_token": id_token,
    }


@app.post("/register")
async def register_client(client_data: ClientRegistrationData = Body(...)):
    # La validazione dei dati è già gestita da Pydantic grazie al modello 'ClientRegistrationData'

    # Store the client credentials securely
    store_client(client_data)

    return {"client_id": client_data.client_id}


@app.post("/refresh")
async def refresh_token(refresh_token_data: RefreshToken = Body(...)):
    try:
        payload = jwt.decode(refresh_token_data.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
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



@app.get("/userinfo")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user.__dict__

@app.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request):
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
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "email"]
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

@app.get("/authorize")
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

    # Genera il codice di autorizzazione
    auth_code = secrets.token_urlsafe(32)

    # Memorizza il codice di autorizzazione
    auth_code_entity = datastore.Entity(key=datastore_client.key("AuthorizationCode"))
    auth_code_entity.update({
        "code": auth_code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
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
        id_token = create_id_token(user, client_id, nonce)
        response_params["id_token"] = id_token

        if response_type == "id_token token":
            access_token = create_access_token(data={"sub": user.username})
            response_params["access_token"] = access_token
            response_params["token_type"] = "bearer"
            response_params["expires_in"] = ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # Reindirizza al client con i parametri appropriati
    redirect_uri = f"{redirect_uri}?{urlencode(response_params)}"
    return RedirectResponse(redirect_uri)

@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "next": request.query_params.get("next")})

@app.post("/login")
async def login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        next: str = Form(None)
):
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
