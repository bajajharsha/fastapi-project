# app/api/user.py
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from app.auth.auth import login_user
from app.db.database import insert_user
from pydantic import BaseModel
from asyncpg.pool import Pool
from api_logger import logger
from app.auth.auth import get_current_user

router = APIRouter()

class CreateUserRequest(BaseModel):
    username: str
    password: str

def get_db_pool(request: Request) -> Pool:
    logger.info(f"Request: {request}")
    logger.info("Getting db pool")
    return request.app.state.pool

@router.post("/create-user/")
async def create_user(request: CreateUserRequest, pool: Pool = Depends(get_db_pool)):
    try:
        user = await insert_user(pool, request.username, request.password)
        return {"message": "User created successfully", "user": user}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error creating user: {e}")
    
    
@router.post("/login/")
async def login(request: CreateUserRequest, response: Response, pool: Pool = Depends(get_db_pool)):
    try:
        login = await login_user(pool, request.username, request.password)
        access_token = login["access_token"]
        refresh_token = login["refresh_token"]
        
        # Set access token in a secure HttpOnly cookie
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,  # Make sure JavaScript cannot access it
            secure=False,    # Use only HTTPS in production
        )
        
        return {"message": "User logged in successfully", "user": login}
    except Exception as e:
        logger.error(f"Error logging in: {e}")
        raise HTTPException(status_code=400, detail=f"Error logging in: {e}")
    
@router.get("/profile/")
async def get_profile(request: Request, current_user: str = Depends(get_current_user)):
    """Get the current user's profile."""
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authorized")
    return {"message": f"Hello, {current_user}"}