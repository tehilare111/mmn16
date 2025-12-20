import secrets
import time
import pyotp
from typing import Dict, Optional
from sqlalchemy.orm import Session
from src.models import User
from src.auth_utils import hash_password, verify_password
from src.exceptions import (
    UserAlreadyExistsError,
    InvalidCredentialsError,
    AccountLockedError,
    CaptchaRequiredError,
    InvalidCaptchaError,
    RateLimitExceededError,
    InvalidTotpError
)
from src.config import (
    HASH_MODE,
    PEPPER,
    PEPPER_SECRET,
    LOCKOUT,
    LOCKOUT_THRESHOLD,
    CAPTCHA,
    CAPTCHA_TOKEN_EXPIRY,
    RATE_LIMIT,
    RATE_LIMIT_MAX_ATTEMPTS,
    RATE_LIMIT_WINDOW_SECONDS,
    TOTP,
    TOTP_WINDOW
)

captcha_tokens: Dict[str, float] = {}
rate_limit_attempts: Dict[str, list] = {}
simulation_tokens: Dict[str, float] = {}


def prepare_password(password: str) -> str:
    if PEPPER:
        return password + PEPPER_SECRET
    return password


def generate_salt() -> Optional[str]:
    if HASH_MODE == "SHA256":
        return secrets.token_hex(8)
    return None


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def register_user(
    username: str, password: str, db: Session, totp_secret: Optional[str] = None
) -> User:
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise UserAlreadyExistsError("Username already exists")

    password_to_hash = prepare_password(password)
    salt = generate_salt()
    hashed = hash_password(password_to_hash, salt=salt)

    if not totp_secret: # in case it wasn't generated from the seeding script
        totp_secret = generate_totp_secret()

    new_user = User(
        username=username,
        hashed_password=hashed,
        salt=salt,
        totp_secret=totp_secret,
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
    username: str,
    password: str,
    captcha_token: Optional[str],
    db: Session,
    simulation_token: Optional[str] = None
) -> User:
    check_rate_limit(username, simulation_token)

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


def generate_simulation_token() -> str:
    token = secrets.token_urlsafe(32)
    expiry_time = time.time() + 3600
    simulation_tokens[token] = expiry_time
    return token


def verify_simulation_token(token: Optional[str]) -> bool:
    if not token:
        return False
    if token not in simulation_tokens:
        return False
    expiry_time = simulation_tokens[token]
    if time.time() > expiry_time:
        del simulation_tokens[token]
        return False
    return True


def check_rate_limit(identifier: str, simulation_token: Optional[str]) -> None:
    if not RATE_LIMIT:
        return

    if verify_simulation_token(simulation_token):
        return

    current_time = time.time()
    window_start = current_time - RATE_LIMIT_WINDOW_SECONDS

    if identifier not in rate_limit_attempts:
        rate_limit_attempts[identifier] = []

    rate_limit_attempts[identifier] = [
        t for t in rate_limit_attempts[identifier] if t > window_start
    ]

    if len(rate_limit_attempts[identifier]) >= RATE_LIMIT_MAX_ATTEMPTS:
        raise RateLimitExceededError(
            f"Rate limit exceeded. Try again in {RATE_LIMIT_WINDOW_SECONDS} seconds"
        )

    rate_limit_attempts[identifier].append(current_time)


def verify_totp_code(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=TOTP_WINDOW)


def authenticate_user_with_totp(
    username: str,
    password: str,
    totp_code: str,
    captcha_token: Optional[str],
    db: Session,
    simulation_token: Optional[str] = None
) -> User:
    user = authenticate_user(username, password, captcha_token, db, simulation_token)

    if TOTP:
        if not user.totp_secret:
            raise InvalidTotpError("TOTP not configured for this user")

        if not verify_totp_code(user.totp_secret, totp_code):
            raise InvalidTotpError("Invalid TOTP code")

    return user
