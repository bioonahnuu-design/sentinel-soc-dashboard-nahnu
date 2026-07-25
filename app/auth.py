import base64
import hashlib
import hmac
import json
import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, Request, Response

from .config import settings

COOKIE_NAME = "sentinel_session"
MAX_FAILURES = 5
FAILURE_WINDOW_SECONDS = 5 * 60
_failed_attempts: dict[str, deque[float]] = defaultdict(deque)
_attempt_lock = Lock()


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded_hash.split(":", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            _b64decode(salt),
            int(iterations),
        )
        return hmac.compare_digest(_b64encode(actual), expected)
    except (TypeError, ValueError):
        return False


def create_session_token(username: str) -> str:
    now = int(time.time())
    payload = _b64encode(json.dumps({
        "sub": username,
        "iat": now,
        "exp": now + settings.auth_session_hours * 3600,
    }, separators=(",", ":")).encode())
    signature = _b64encode(
        hmac.new(settings.auth_secret.encode(), payload.encode(), hashlib.sha256).digest()
    )
    return f"{payload}.{signature}"


def read_session_token(token: str | None) -> str | None:
    if not token or "." not in token:
        return None
    try:
        payload, signature = token.split(".", 1)
        expected = _b64encode(
            hmac.new(settings.auth_secret.encode(), payload.encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(signature, expected):
            return None
        data = json.loads(_b64decode(payload))
        if data.get("exp", 0) < int(time.time()):
            return None
        if data.get("sub") != settings.soc_username:
            return None
        return data["sub"]
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def current_user(request: Request) -> str | None:
    return read_session_token(request.cookies.get(COOKIE_NAME))


def set_session_cookie(response: Response, username: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        create_session_token(username),
        max_age=settings.auth_session_hours * 3600,
        httponly=True,
        secure=settings.auth_secure_cookie,
        samesite="strict",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        COOKIE_NAME,
        httponly=True,
        secure=settings.auth_secure_cookie,
        samesite="strict",
        path="/",
    )


def check_login_rate_limit(client_key: str) -> None:
    now = time.time()
    with _attempt_lock:
        attempts = _failed_attempts[client_key]
        while attempts and attempts[0] < now - FAILURE_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= MAX_FAILURES:
            raise HTTPException(429, "Too many failed login attempts. Try again in 5 minutes.")


def record_failed_login(client_key: str) -> None:
    with _attempt_lock:
        _failed_attempts[client_key].append(time.time())


def clear_failed_logins(client_key: str) -> None:
    with _attempt_lock:
        _failed_attempts.pop(client_key, None)
