from typing import Optional
from pydantic import BaseModel


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str
    captcha_token: Optional[str] = None
    simulation_token: Optional[str] = None


class LoginTotpRequest(BaseModel):
    username: str
    password: str
    totp_code: str
    captcha_token: Optional[str] = None
    simulation_token: Optional[str] = None
