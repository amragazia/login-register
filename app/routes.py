from __future__ import annotations
from typing import Any  # type: ignore
from datetime import datetime, timedelta, timezone  # type: ignore
import os

from fastapi import Depends, FastAPI, HTTPException, status, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer

import jwt  # type: ignore
import secrets

# local imports
from .schemas import User, UserUpdate
from .database import DataBase
from .main import hash_func, is_legacy_password_hash, verify_password

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://192.168.1.11:5500",
        "http://127.0.0.1:9999",
    ],
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods (POST, GET, OPTIONS, etc.)
    allow_headers=["*"],  # Allows all headers (like our 'Authorization' header)
)

db = DataBase()
db.create_table_users()

SECRET_KEY = os.getenv("SECRET_KEY", "development-only-change-this-secret-key")
ALGORITHM = "HS256"
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

#! session-based Auth
# 1. In-Memory Session Store (For learning purposes)
active_sessions: dict[str, str] = {}


async def get_current_user(request: Request) -> str:

    session_id = request.cookies.get("session_id")

    if not session_id or session_id not in active_sessions:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return active_sessions[session_id]


#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


# * Token based Auth (JWT) [Archived] *#

# def create_access_token(data: dict[str, Any]) -> str:
#     to_encode = data.copy()
#     expire = datetime.now(timezone.utc) + timedelta(minutes=30)
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)  # type: ignore


# async def get_current_user(token: str = Depends(oauth2_scheme)):

#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )

#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # type: ignore
#         username = payload.get("sub")
#         if not isinstance(username, str):
#             raise credentials_exception
#         return username
#     except jwt.InvalidTokenError:
#         raise credentials_exception

# *****************************************************


@app.post("/create-user", status_code=201)
def create_user(user: User):
    password_hash = hash_func(user.password)

    if not db.insert_user(username=user.username, password_hash=password_hash):
        raise HTTPException(status_code=409, detail="Username already exists")

    return {"message": "User Created"}


#! login endpoint with session-based Auth
@app.post("/login")
def login(data: User, response: Response):

    user = db.get_user(username=data.username)

    if user is None or not verify_password(data.password, user[2]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Upgrade legacy hashes on successful login
    if is_legacy_password_hash(user[2]):
        db.update_user(data.username, data.username, hash_func(data.password))

    session_id = secrets.token_hex(16)
    active_sessions[session_id] = data.username

    response.set_cookie(
        key="session_id", value=session_id, httponly=True, samesite="lax"
    )

    return {"message": "Logged in successfully"}


# * login endpoint with JWT Auth
# @app.post("/login")
# def login(data: User):

#     user = db.get_user(username=data.username)

#     if user is None or not verify_password(data.password, user[2]):
#         raise HTTPException(status_code=401, detail="Invalid username or password")

#     if is_legacy_password_hash(user[2]):
#         db.update_user(data.username, data.username, hash_func(data.password))

#     access_token = create_access_token(data={"sub": data.username})

#     return {
#         "message": "Logged in successfully",
#         "access_token": access_token,
#         "token_type": "bearer",
#     }

# ****************************************************


@app.get("/home/dashboard")
async def get_dashboard(username: str = Depends(get_current_user)):

    if username != ADMIN_USERNAME:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required"
        )

    return {
        "secret_data": f"Welcome to the highly classified dashboard, {username}!",
        "balance": "$1,000,000",
    }


@app.get("/home/{username}")
def home(username: str, current_user: str = Depends(get_current_user)):

    user_record = db.get_user(username=username)

    if user_record is None:
        raise HTTPException(status_code=404, detail="User not found")

    if username != current_user:
        raise HTTPException(status_code=403, detail="Authentication Failed")

    return {
        "id": user_record[0],
        "username": user_record[1],
    }


# * update endpoint with JWT Auth
# @app.put("/home/{username}/update")
# def update(
#     username: str, updated: UserUpdate, current_user: str = Depends(get_current_user)
# ):

#     user_record = db.get_user(username=username)

#     if user_record is None:
#         raise HTTPException(status_code=404, detail="User not found")

#     if username != current_user:
#         raise HTTPException(
#             status_code=403, detail="Not authorized to update this profile"
#         )

#     new_password_hash = (
#         hash_func(updated.password) if updated.password else user_record[2]
#     )
#     new_username = updated.username if updated.username else username

#     success = db.update_user(
#         username=username,
#         new_username=new_username,
#         new_password_hash=new_password_hash,
#     )

#     if not success:
#         raise HTTPException(status_code=409, detail="That username is already taken")

#     new_token = create_access_token(data={"sub": new_username})

#     return {"updated": "success", "access_token": new_token}

# ********************************************************


#! update endpoint with session-based Auth
@app.put("/home/{username}/update")
def update(
    username: str,
    updated: UserUpdate,
    response: Response,
    request: Request,
    current_user: str = Depends(get_current_user),
):

    user_record = db.get_user(username=username)

    if user_record is None:
        raise HTTPException(status_code=404, detail="User not found")

    if username != current_user:
        raise HTTPException(
            status_code=403, detail="Not authorized to update this profile"
        )

    new_password_hash = (
        hash_func(updated.password) if updated.password else user_record[2]
    )
    new_username = updated.username if updated.username else username

    success = db.update_user(
        username=username,
        new_username=new_username,
        new_password_hash=new_password_hash,
    )

    if not success:
        raise HTTPException(status_code=409, detail="That username is already taken")

    # Clean up the previous session ID to avoid stale entries
    old_session_id = request.cookies.get("session_id")
    if old_session_id in active_sessions:
        del active_sessions[old_session_id]

    new_session_id = secrets.token_hex(16)
    active_sessions[new_session_id] = new_username

    response.set_cookie(
        key="session_id", value=new_session_id, httponly=True, samesite="lax"
    )
    return {"updated": "success"}


@app.delete("/home/{username}/delete-user")
def delete_user(username: str, current_user: str = Depends(get_current_user)):

    if username != current_user:
        raise HTTPException(
            status_code=403, detail="Not authorized to delete this profile"
        )

    success = db.delete_user(username=username)

    if not success:
        raise HTTPException(status_code=404, detail="User not found")

    return {"deleted": "Success"}


@app.get("/home/{username}/view-users")
def get_accounts(
    username: str,
    user_to_view: str | None = None,
    current_user: str = Depends(get_current_user),
):

    user_record = db.get_user(username=username)

    if user_record is None:
        raise HTTPException(status_code=404, detail="User not found")

    if username != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to view users")

    if user_record[1] != ADMIN_USERNAME:
        raise HTTPException(status_code=403, detail="Not authorized to view users")

    if user_to_view is None:
        data = db.get_all_users()

    else:
        data = db.get_user(username=user_to_view)

    return {"users": data}


# * for session-based Auth
@app.post("/logout")
def server_logout(request: Request, response: Response):

    session_id = request.cookies.get("session_id")

    if session_id in active_sessions:
        del active_sessions[session_id]

    response.delete_cookie("session_id")

    return {"message": "Logged out successfully"}
