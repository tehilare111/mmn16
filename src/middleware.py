import time
import json
from datetime import datetime
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from src.config import (
    GROUP_SEED,
    HASH_MODE,
    RATE_LIMIT,
    LOCKOUT,
    CAPTCHA,
    PEPPER
)
from src.logger import setup_logger

logger = setup_logger()


class LoginLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in ["/login", "/login_totp"]:
            start_time = time.time()

            body = await request.body()
            try:
                body_json = json.loads(body.decode()) if body else {}
                username = body_json.get("username", "")
            except (json.JSONDecodeError, UnicodeDecodeError):
                username = ""

            async def receive():
                return {"type": "http.request", "body": body}

            request._receive = receive

            response = await call_next(request)

            latency_ms = int((time.time() - start_time) * 1000)

            result = "success" if response.status_code == 200 else "failure"

            protection_flags = {
                "RATE_LIMIT": RATE_LIMIT,
                "LOCKOUT": LOCKOUT,
                "CAPTCHA": CAPTCHA,
                "PEPPER": PEPPER,
            }

            log_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "group_seed": GROUP_SEED,
                "username": username,
                "hash_mode": HASH_MODE,
                "protection_flags": protection_flags,
                "result": result,
                "latency_ms": latency_ms,
            }

            logger.info(json.dumps(log_entry))

            return response

        return await call_next(request)
