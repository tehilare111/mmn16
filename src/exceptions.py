class SecurityException(Exception):
    """Base exception for all security-related errors."""


class UserAlreadyExistsError(SecurityException):
    """Raised when attempting to register a username that already exists."""


class InvalidCredentialsError(SecurityException):
    """Raised when authentication credentials are invalid."""


class AccountLockedError(SecurityException):
    """Raised when an account is locked due to too many failed attempts."""


class CaptchaRequiredError(SecurityException):
    """Raised when CAPTCHA token is required but not provided."""


class InvalidCaptchaError(SecurityException):
    """Raised when CAPTCHA token is invalid or expired."""


class RateLimitExceededError(SecurityException):
    """Raised when rate limit is exceeded for login attempts."""


class InvalidTotpError(SecurityException):
    """Raised when TOTP code is invalid or expired."""
