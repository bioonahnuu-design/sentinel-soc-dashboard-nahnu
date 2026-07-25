import hmac
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from .api import router
from .auth import (
    clear_failed_logins,
    clear_session_cookie,
    check_login_rate_limit,
    current_user,
    record_failed_login,
    set_session_cookie,
    verify_password,
)
from .config import settings
from .database import Base, engine


ROOT = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="Sentinel SOC Dashboard", version="1.0.0", lifespan=lifespan)
app.include_router(router)
app.mount("/static", StaticFiles(directory=ROOT / "frontend"), name="static")


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


def apply_security_headers(request: Request, response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path in {"/", "/login"}:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'"
        )
    if request.url.path.startswith(("/api/", "/auth/", "/health")):
        response.headers["Cache-Control"] = "no-store"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.middleware("http")
async def security_and_auth(request: Request, call_next):
    path = request.url.path
    public = (
        path == "/login"
        or path == "/health"
        or path.startswith("/health/")
        or path in {"/auth/login", "/auth/logout"}
        or path.startswith("/static/")
    )
    if not public and not current_user(request):
        if path in {"/", "/docs", "/redoc"}:
            return apply_security_headers(request, RedirectResponse("/login", status_code=303))
        return apply_security_headers(
            request,
            JSONResponse(status_code=401, content={"detail": "Authentication required"}),
        )

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        expected_origin = str(request.base_url).rstrip("/")
        if origin and origin.rstrip("/") != expected_origin:
            return apply_security_headers(
                request,
                JSONResponse(status_code=403, content={"detail": "Invalid request origin"}),
            )

    response = await call_next(request)
    return apply_security_headers(request, response)


@app.get("/login", include_in_schema=False)
def login_page(request: Request):
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    return FileResponse(ROOT / "frontend" / "login.html")


@app.post("/auth/login", include_in_schema=False)
def login(payload: LoginRequest, request: Request):
    client_key = request.client.host if request.client else "unknown"
    check_login_rate_limit(client_key)
    username_ok = hmac.compare_digest(payload.username.strip(), settings.soc_username)
    password_ok = verify_password(payload.password, settings.soc_password_hash)
    if not username_ok or not password_ok:
        record_failed_login(client_key)
        return JSONResponse(status_code=401, content={"detail": "Invalid username or password"})
    clear_failed_logins(client_key)
    response = JSONResponse({"status": "authenticated", "username": settings.soc_username})
    set_session_cookie(response, settings.soc_username)
    return response


@app.get("/auth/me", include_in_schema=False)
def auth_me(request: Request):
    return {"username": current_user(request), "role": "SOC Analyst"}


@app.post("/auth/logout", include_in_schema=False)
def logout():
    response = JSONResponse({"status": "logged_out"})
    clear_session_cookie(response)
    return response


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(ROOT / "frontend" / "index.html")


@app.get("/health")
def health():
    return readiness()


@app.get("/health/live", include_in_schema=False)
def liveness():
    return {"status": "alive"}


@app.get("/health/ready", include_in_schema=False)
def readiness():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"status": "healthy", "database": "connected"}
    except SQLAlchemyError:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "database": "disconnected"},
        )
