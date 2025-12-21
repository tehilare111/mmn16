import json
import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

with open("data/users.json") as f:
    USER_DATA = json.load(f)
    GROUP_SEED = USER_DATA["group_seed"]
    ALL_PASSWORDS = [user["password"] for user in USER_DATA["users"]]
    USER_SECRETS = {user["username"]: user["totp_secret"] for user in USER_DATA["users"]}
    USER_PASSWORDS = {user["username"]: user["password"] for user in USER_DATA["users"]}
    USER_CATEGORIES = {user["username"]: user["category"] for user in USER_DATA["users"]}

HASH_MODE = os.getenv("HASH_MODE", "SHA256")
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT", "false").lower() == "true"
LOCKOUT_ENABLED = os.getenv("LOCKOUT", "false").lower() == "true"
CAPTCHA_ENABLED = os.getenv("CAPTCHA", "false").lower() == "true"
PEPPER_ENABLED = os.getenv("PEPPER", "false").lower() == "true"
TOTP_ENABLED = os.getenv("TOTP", "false").lower() == "true"

BASE_URL = "http://localhost:8001"


if __name__ == "__main__":
    import sys
    sys.path.insert(0, '.')
    from tests.brute_force import brute_force_attack
    from tests.password_spraying import password_spraying_attack

    asyncio.run(brute_force_attack("weak_user_01"))
    asyncio.run(password_spraying_attack(["strong_user_09", "strong_user_10"]))
