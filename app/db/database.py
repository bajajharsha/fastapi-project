# app/db/database.py
import asyncpg
from fastapi import FastAPI
from passlib.context import CryptContext  # Hash passwords
from api_logger import logger

DATABASE_CONFIG = {
    "user": "postgres",
    "password": "harsha",
    "database": "test",
    "host": "localhost",
    "port": 5433
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_db_pool():
    """Create and return a connection pool."""
    pool = await asyncpg.create_pool(**DATABASE_CONFIG)
    logger.info("Database pool created")
    return pool

async def create_users_table(pool):
    """Create the users table if it doesn't exist."""
    async with pool.acquire() as connection:
        await connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL
            );
        """)

async def insert_user(pool, username: str, password: str):
    password_hash = get_password_hash(password)
    """Insert a new user into the users table."""
    query = """
    INSERT INTO users (username, password)
    VALUES ($1, $2)
    RETURNING id, username;
    """
    async with pool.acquire() as connection:
        result = await connection.fetchrow(query, username, password_hash)
        return {"id": result["id"], "username": result["username"]}

async def authenticate_user(pool, username: str, password: str):
    """Authenticate a user by username and password."""
    query = """
    SELECT * FROM users
    WHERE username = $1;
    """
    async with pool.acquire() as connection:
        user = await connection.fetchrow(query, username)
        logger.info(f"Fetched User: {user}")
        if not user:
            raise ValueError("User not found")
        if not pwd_context.verify(password, user["password"]):
            raise ValueError("Incorrect password")
        return {"id": user['id'], "username": user['username']}


# FastAPI lifespan
async def lifespan(app: FastAPI):
    """Manage the app lifespan, including DB pool setup and cleanup."""
    pool = await get_db_pool() 
    await create_users_table(pool)
    app.state.pool = pool 

    yield  

    await pool.close()  
