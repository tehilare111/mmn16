import os
from dotenv import load_dotenv
from typing import Literal, cast

load_dotenv()

GROUP_SEED = int(os.getenv("GROUP_SEED", "1170596"))
PEPPER_SECRET = os.getenv("PEPPER_SECRET", "")

HASH_MODE_STR = os.getenv("HASH_MODE", "SHA256")
HASH_MODE: Literal["SHA256", "BCRYPT", "ARGON2ID"] = cast(
    Literal["SHA256", "BCRYPT", "ARGON2ID"], HASH_MODE_STR
)

RATE_LIMIT = os.getenv("RATE_LIMIT", "false").lower() == "true"
LOCKOUT = os.getenv("LOCKOUT", "false").lower() == "true"
LOCKOUT_THRESHOLD = 3
CAPTCHA = os.getenv("CAPTCHA", "false").lower() == "true"
CAPTCHA_TOKEN_EXPIRY = 300
PEPPER = os.getenv("PEPPER", "false").lower() == "true"
