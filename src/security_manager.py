import secrets
import time
from typing import Dict, Optional
from sqlalchemy.orm import Session
from src.models import User
from src.auth_utils import hash_password, verify_password
from src.exceptions import (
    UserAlreadyExistsError,
    InvalidCredentialsError,
    AccountLockedError,
    CaptchaRequiredError,
    InvalidCaptchaError
)
from src.config import (
    HASH_MODE,
    PEPPER,
    PEPPER_SECRET,
    LOCKOUT,
    LOCKOUT_THRESHOLD,
    CAPTCHA,
    CAPTCHA_TOKEN_EXPIRY
)

captcha_tokens: Dict[str, float] = {}


def prepare_password(password: str) -> str:
    if PEPPER:
        return password + PEPPER_SECRET
    return password


def generate_salt() -> Optional[str]:
    if HASH_MODE == "SHA256":
        return secrets.token_hex(8)
    return None


def register_user(
    username: str, password: str, db: Session
) -> User:
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise UserAlreadyExistsError("Username already exists")

    password_to_hash = prepare_password(password)
    salt = generate_salt()
    hashed = hash_password(password_to_hash, salt=salt)

    new_user = User(
        username=username,
        hashed_password=hashed,
        salt=salt,
        failed_attempts=0
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


def check_account_lockout(user: User) -> None:
    if LOCKOUT and user.failed_attempts >= LOCKOUT_THRESHOLD:
        raise AccountLockedError(
            "Account locked due to too many failed attempts"
        )


def validate_captcha(captcha_token: Optional[str]) -> None:
    if not CAPTCHA:
        return

    if not captcha_token:
        raise CaptchaRequiredError("CAPTCHA token required")

    if not verify_captcha_token(captcha_token):
        raise InvalidCaptchaError("Invalid CAPTCHA token")


def authenticate_user(
    username: str, password: str, captcha_token: Optional[str], db: Session
) -> User:
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise InvalidCredentialsError("Invalid username or password")

    check_account_lockout(user)
    validate_captcha(captcha_token)

    password_to_verify = prepare_password(password)
    is_valid = verify_password(password_to_verify, user.hashed_password)

    if not is_valid:
        user.failed_attempts += 1
        db.commit()
        raise InvalidCredentialsError("Invalid username or password")

    user.failed_attempts = 0
    db.commit()

    return user


def generate_captcha_token() -> str:
    token = secrets.token_urlsafe(32)
    expiry_time = time.time() + CAPTCHA_TOKEN_EXPIRY
    captcha_tokens[token] = expiry_time
    return token


def verify_captcha_token(token: str) -> bool:
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
