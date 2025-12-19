from typing import Optional
from passlib.context import CryptContext
from passlib.hash import argon2, bcrypt, sha256_crypt
from src.config import HASH_MODE

pwd_context = CryptContext(schemes=["bcrypt", "argon2"], deprecated="auto")


def hash_password(password: str, salt: Optional[str] = None) -> str:
    if HASH_MODE == "BCRYPT":
        return bcrypt.hash(password, rounds=12)
    elif HASH_MODE == "ARGON2ID":
        return argon2.hash(password, time_cost=1, memory_cost=65536)
    elif HASH_MODE == "SHA256":
        return sha256_crypt.hash(password, salt=salt)
    else:
        raise ValueError(f"Unknown hash mode: {HASH_MODE}")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if HASH_MODE == "BCRYPT":
        return bcrypt.verify(plain_password, hashed_password)
    elif HASH_MODE == "ARGON2ID":
        return argon2.verify(plain_password, hashed_password)
    elif HASH_MODE == "SHA256":
        return sha256_crypt.verify(plain_password, hashed_password)
    else:
        raise ValueError(f"Unknown hash mode: {HASH_MODE}")
