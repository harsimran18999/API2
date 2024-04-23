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

# Data model for User Credentials
class UserCredentials(BaseModel):
    username: str
    password: str

# Security helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependency to authenticate users
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")def authenticate_user(username: str, password: str):
    user = users_db.get(username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_user_token(user: User):
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return access_token

# Routes
@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_user_token(user)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/", response_model=User)
def create_user(user: UserInDB):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    user.hashed_password = get_password_hash(user.hashed_password)
    users_db[user.username] = user
    credits_db[user.username] = user.credits
    return user

@app.get("/users/me/", response_model=User)
def read_users_me(token: str = Depends(oauth2_scheme)):
    username = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sub"]
    return users_db[username]

@app.get("/users/", response_model=List[User])
def read_users():
    return list(users_db.values())

@app.get("/users/{username}", response_model=User)
def read_user(username: str):
    if username not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    return users_db[username]