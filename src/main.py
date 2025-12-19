import secrets
import time
from typing import Dict
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from src.database import engine, get_db
from src.models import Base, User
from src.schemas import RegisterRequest, LoginRequest
from src.middleware import LoginLoggerMiddleware
from src.auth_utils import hash_password, verify_password
from src.config import (
    HASH_MODE,
    PEPPER,
    PEPPER_SECRET,
    LOCKOUT,
    LOCKOUT_THRESHOLD,
    CAPTCHA,
    CAPTCHA_TOKEN_EXPIRY
)

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(LoginLoggerMiddleware)

captcha_tokens: Dict[str, float] = {}


@app.post("/register")
async def register(request: RegisterRequest, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == request.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    password_to_hash = request.password
    if PEPPER:
        password_to_hash = request.password + PEPPER_SECRET

    salt = None
    if HASH_MODE == "SHA256":
        salt = secrets.token_hex(8)

    hashed = hash_password(password_to_hash, salt=salt)

    new_user = User(
        username=request.username, hashed_password=hashed, salt=salt, failed_attempts=0
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully", "username": new_user.username}


@app.post("/login")
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == request.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if LOCKOUT and user.failed_attempts >= LOCKOUT_THRESHOLD:
        raise HTTPException(
            status_code=403, detail="Account locked due to too many failed attempts"
        )

    if CAPTCHA and not request.captcha_token:
        raise HTTPException(status_code=400, detail="CAPTCHA token required")

    if CAPTCHA and request.captcha_token:
        captcha_valid = await verify_captcha(request.captcha_token)
        if not captcha_valid:
            raise HTTPException(status_code=400, detail="Invalid CAPTCHA token")

    password_to_verify = request.password
    if PEPPER:
        password_to_verify = request.password + PEPPER_SECRET

    is_valid = verify_password(password_to_verify, user.hashed_password)

    if not is_valid:
        user.failed_attempts += 1
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    user.failed_attempts = 0
    db.commit()

    return {"message": "Login successful", "username": user.username}


async def verify_captcha(token: str) -> bool:
    if not token:
        return False
    if token not in captcha_tokens:
        return False
    expiry_time = captcha_tokens[token]
    if time.time() > expiry_time:
        del captcha_tokens[token]
        return False
    del captcha_tokens[token]
    return True


@app.post("/login_totp")
async def login_totp():
    pass


@app.get("/admin/get_captcha_token")
async def get_captcha_token():
    token = secrets.token_urlsafe(32)
    expiry_time = time.time() + CAPTCHA_TOKEN_EXPIRY
    captcha_tokens[token] = expiry_time
    return {"captcha_token": token}
