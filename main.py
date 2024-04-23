from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

app = FastAPI()

# Example data - Replace this with your database implementation
users_db = {}
tokens_db = {}
credits_db = {}
jobs_queue = []

# Secret key to sign JWT tokens
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Data model for User
class User(BaseModel):
    username: str
    email: str
    hashed_password: str

# Data model for User Credentials
class UserInDB(User):
    credits: int = 0

# Data model for JWT Token
class Token(BaseModel):
    access_token: str
    token_type: str