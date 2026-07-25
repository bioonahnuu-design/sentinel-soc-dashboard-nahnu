from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


LOCAL_AUTH_SECRET = "local-development-secret-change-before-hosting"


class Settings(BaseSettings):
    app_env: str = "local"
    database_url: str = "sqlite:///./soc_dashboard.db"

    brute_force_threshold: int = 5
    brute_force_window_minutes: int = 10

    soc_username: str = "analyst"
    soc_password_hash: str = ""

    auth_secret: str = LOCAL_AUTH_SECRET
    auth_session_hours: int = 8
    auth_secure_cookie: bool = False

    db_pool_size: int = 5
    db_max_overflow: int = 10

    @model_validator(mode="after")
    def validate_production_security(self):
        if self.app_env.lower() != "production":
            return self

        if (
            self.auth_secret == LOCAL_AUTH_SECRET
            or len(self.auth_secret) < 32
        ):
            raise ValueError(
                "AUTH_SECRET must be changed to at least 32 characters "
                "in production"
            )

        if not self.soc_password_hash:
            raise ValueError(
                "SOC_PASSWORD_HASH must be configured in production"
            )

        if not self.auth_secure_cookie:
            raise ValueError(
                "AUTH_SECURE_COOKIE must be true in production"
            )

        if (
            self.database_url.startswith(("postgresql", "postgres"))
            and "sslmode=" not in self.database_url
        ):
            raise ValueError(
                "Production PostgreSQL DATABASE_URL must include "
                "sslmode=require or sslmode=verify-full"
            )

        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )


settings = Settings()