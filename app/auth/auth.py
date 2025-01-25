# app/auth/jwt_handler.py
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException, status, Request
# OAuth2PasswordBearer: A helper to retrieve and validate bearer tokens from HTTP requests.
# OAuth2PasswordRequestForm: Automatically parses username and password from form data (used during login).
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
# jwt.encode: Creates a JWT.
# jwt.decode: Validates and parses a JWT.
from jose import JWTError, jwt
from passlib.context import CryptContext   
from app.db.database import authenticate_user
from api_logger import logger

SECRET_KEY = "f2e42452d3d0eee523a7fea87c41a0c968509a9be5d2dd615ea8ab9d94db938f"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# deprecated - the context will automatically handle deprecated schemes.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

'''
fastapi.security module
handle OAuth2 authentication with password and bearer token.
tokenUrl - URL endpoint where the client can obtain the token
'''
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")    

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    logger.info(f"Creating access token for user: {data}")
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
        
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def login_user(pool, username, password):
    logger.info(f"Logging in user: {username}")
    user = await authenticate_user(pool, username, password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    logger.info(f"User: {user}")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_DAYS)
    access_token = create_access_token(
        data={"sub": user["username"]}, 
        expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(
        data={"sub": user["username"]}, 
        expires_delta=refresh_token_expires
    )
    return {"access_token": access_token, "refresh_token": refresh_token ,"token_type": "bearer"}


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_token(token: str):
    """Verify the JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(request: Request):
    """Get the current user by extracting the token from cookies."""
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authorized")
    payload = verify_token(token)  # Verify token function as before
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    return username