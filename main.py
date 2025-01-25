# main.py
from fastapi import FastAPI
from app.api.user import router as user_router
from app.db.database import lifespan

app = FastAPI(lifespan=lifespan)

# Include the user router
app.include_router(user_router, prefix="/user")

@app.get("/")
async def read_root():
    return {"message": "Welcome to the API"}
