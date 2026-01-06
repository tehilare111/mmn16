import asyncio
from typing import Optional
import httpx


# Constants - increased timeout for slow hash algorithms like bcrypt
HTTP_CLIENT_TIMEOUT_SECONDS: float = 60.0
MAX_RETRY_ATTEMPTS: int = 3
RETRY_BACKOFF_BASE: int = 5  # seconds, used for exponential backoff


# Custom Exceptions
class AttackException(Exception):
    """Base exception for all attack-related errors."""
    pass


class NetworkError(AttackException):
    """Raised when network communication with the server fails."""
    pass


class CaptchaTokenError(AttackException):
    """Raised when unable to retrieve or use a CAPTCHA token."""
    pass


class ServerResponseError(AttackException):
    """Raised when server returns an unexpected or invalid response."""
    pass


async def get_captcha_token(client: httpx.AsyncClient, base_url: str) -> Optional[str]:
    try:
        response = await client.get(f"{base_url}/admin/get_captcha_token")
        if response.status_code == 200:
            data = response.json()
            return data.get("captcha_token")
        else:
            raise ServerResponseError(
                f"Failed to get CAPTCHA token. Status code: {response.status_code}"
            )
    except httpx.RequestError as e:
        raise NetworkError(f"Network error while requesting CAPTCHA token: {e}") from e
    except httpx.HTTPStatusError as e:
        raise ServerResponseError(f"HTTP error while requesting CAPTCHA token: {e}") from e
    except Exception as e:
        raise CaptchaTokenError(f"Unexpected error getting CAPTCHA token: {e}") from e


def is_account_locked(response: httpx.Response) -> bool:
    if response.status_code == 403:
        try:
            response_data = response.json()
            detail = response_data.get("detail", "").lower()
            return "locked" in detail or "too many" in detail
        except (ValueError, KeyError):
            pass
    return False


async def make_login_attempt(client: httpx.AsyncClient, base_url: str, endpoint: str, payload: dict) -> httpx.Response:
    response = await client.post(f"{base_url}{endpoint}", json=payload)

    if response.status_code == 400:
        try:
            response_data = response.json()
            if "captcha" in response_data.get("detail", "").lower():
                try:
                    captcha_token = await get_captcha_token(client, base_url)
                    payload["captcha_token"] = captcha_token
                    response = await client.post(f"{base_url}{endpoint}", json=payload)
                except (CaptchaTokenError, NetworkError, ServerResponseError):
                    pass
        except (ValueError, KeyError):
            pass

    retry_count: int = 0
    while response.status_code == 429 and retry_count < MAX_RETRY_ATTEMPTS:
        wait_time: int = RETRY_BACKOFF_BASE * (2 ** retry_count)
        await asyncio.sleep(wait_time)
        response = await client.post(f"{base_url}{endpoint}", json=payload)
        retry_count += 1

    return response
