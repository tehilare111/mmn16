from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import engine, get_db
from src.models import Base
from src.schemas import RegisterRequest, LoginRequest
from src.middleware import LoginLoggerMiddleware
from src.security_manager import (
    register_user,
    authenticate_user,
    generate_captcha_token,
    generate_simulation_token
)
from src.exceptions import (
    UserAlreadyExistsError,
    InvalidCredentialsError,
    AccountLockedError,
    CaptchaRequiredError,
    InvalidCaptchaError,
    RateLimitExceededError
)

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(LoginLoggerMiddleware)


@app.post("/register")
async def register(request: RegisterRequest, db: Session = Depends(get_db)):
    try:
        new_user = register_user(request.username, request.password, db)
        return {
            "message": "User registered successfully",
            "username": new_user.username
        }
    except UserAlreadyExistsError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.post("/login")
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    try:
        user = authenticate_user(
            request.username,
            request.password,
            request.captcha_token,
            db,
            request.simulation_token
        )
        return {"message": "Login successful", "username": user.username}
    except RateLimitExceededError as e:
        raise HTTPException(status_code=429, detail=str(e)) from e
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=401, detail=str(e)) from e
    except AccountLockedError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    except (CaptchaRequiredError, InvalidCaptchaError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.post("/login_totp")
async def login_totp():
    pass


@app.get("/admin/get_captcha_token")
async def get_captcha_token():
    token = generate_captcha_token()
    return {"captcha_token": token}


@app.get("/admin/get_simulation_token")
async def get_simulation_token():
    token = generate_simulation_token()
    return {"simulation_token": token}
