import os
from datetime import datetime, timezone

import pytest

os.environ["DATABASE_URL"] = "sqlite:///./test_api.db"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.config import Settings  # noqa: E402


def login(client: TestClient):
    response = client.post(
        "/auth/login",
        json={"username": "analyst", "password": "Sentinel2026!"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "authenticated"
    assert "httponly" in response.headers["set-cookie"].lower()
    assert "samesite=strict" in response.headers["set-cookie"].lower()


def test_authentication_flow():
    with TestClient(app, follow_redirects=False) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/health/live").json() == {"status": "alive"}
        assert client.get("/health/ready").json() == {"status": "healthy", "database": "connected"}
        assert client.get("/").status_code == 303
        assert client.get("/api/alerts").status_code == 401
        assert client.get("/openapi.json").status_code == 401
        assert client.get("/login").status_code == 200
        bad = client.post(
            "/auth/login",
            json={"username": "analyst", "password": "wrong-password"},
        )
        assert bad.status_code == 401
        login(client)
        assert client.get("/").status_code == 200
        assert client.get("/auth/me").json()["role"] == "SOC Analyst"
        assert client.post("/auth/logout").status_code == 200
        assert client.get("/api/alerts").status_code == 401


def test_production_configuration_guards():
    with pytest.raises(ValueError, match="AUTH_SECRET"):
        Settings(
            app_env="production",
            database_url="postgresql+psycopg://user:pass@host/db?sslmode=require",
            auth_secure_cookie=True,
        )
    with pytest.raises(ValueError, match="sslmode"):
        Settings(
            app_env="production",
            database_url="postgresql+psycopg://user:pass@host/db",
            auth_secret="x" * 40,
            auth_secure_cookie=True,
        )
    valid = Settings(
        app_env="production",
        database_url="postgresql+psycopg://user:pass@host/db?sslmode=require",
        auth_secret="x" * 40,
        auth_secure_cookie=True,
    )
    assert valid.app_env == "production"


def test_dashboard_and_log_ingestion():
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.json() == {"status": "healthy", "database": "connected"}
        assert health.headers["cache-control"] == "no-store"
        login(client)
        dashboard = client.get("/")
        assert dashboard.status_code == 200
        assert dashboard.headers["x-content-type-options"] == "nosniff"
        assert dashboard.headers["x-frame-options"] == "DENY"
        assert "default-src 'self'" in dashboard.headers["content-security-policy"]
        assert "escapeHTML" in client.get("/static/app.js").text
        response = client.post(
            "/api/logs",
            json={
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "203.0.113.11",
                "username": "analyst",
                "event_type": "login",
                "status": "success",
                "country": "Indonesia",
            },
        )
        assert response.status_code == 201
        assert client.get("/api/stats/overview").json()["total_events"] >= 1
        assert client.get("/api/stats/overview?hours=2").status_code == 422
        assert len(client.get("/api/logs?hours=24&q=analyst").json()) >= 1
        assert client.get("/api/logs?hours=24&q=definitely-missing-user").json() == []
        successful = client.get("/api/logs?hours=24&status=success").json()
        assert len(successful) >= 1
        assert all(item["status"] == "success" for item in successful)
        assert client.get("/api/logs?hours=24&status=invalid").status_code == 422


def test_csv_and_json_log_upload():
    now = datetime.now(timezone.utc).isoformat()
    csv_data = (
        "timestamp,source_ip,username,event_type,status,country\n"
        f"{now},203.0.113.21,csv-user,login,failed,Indonesia\n"
        f"{now},not-an-ip,bad-user,login,failed,Indonesia\n"
    )
    with TestClient(app) as client:
        login(client)
        response = client.post(
            "/api/logs/upload",
            files={"file": ("security-logs.csv", csv_data, "text/csv")},
        )
        assert response.status_code == 200
        assert response.json()["imported"] == 1
        assert response.json()["rejected"] == 1

        json_data = [
            {
                "timestamp": now,
                "source_ip": "2001:db8::25",
                "username": "json-user",
                "event_type": "login",
                "status": "success",
                "country": "high-risk",
            }
        ]
        response = client.post(
            "/api/logs/upload",
            files={"file": ("security-logs.json", __import__("json").dumps(json_data), "application/json")},
        )
        assert response.status_code == 200
        assert response.json()["imported"] == 1
        assert response.json()["alerts_created"] == 1

        alerts = client.get("/api/alerts?severity=medium").json()["items"]
        assert alerts
        detail = client.get(f"/api/alerts/{alerts[0]['id']}")
        assert detail.status_code == 200
        assert detail.json()["incident_id"].startswith("INC-")
        assert detail.json()["description"]
        assert detail.json()["log"]["username"] == "json-user"
        assert detail.json()["log"]["source_ip"] == "2001:db8::25"
        report = client.get(f"/api/alerts/{alerts[0]['id']}/report")
        assert report.status_code == 200
        assert report.headers["content-type"].startswith("text/html")
        assert detail.json()["incident_id"] in report.text
        assert "Print / Save as PDF" in report.text
        assert "json-user" in report.text
        assert client.get("/api/alerts/999999").status_code == 404
        assert client.get("/api/alerts/999999/report").status_code == 404


def test_upload_rejects_unsupported_file():
    with TestClient(app) as client:
        login(client)
        response = client.post(
            "/api/logs/upload",
            files={"file": ("logs.txt", "not supported", "text/plain")},
        )
        assert response.status_code == 415


def test_report_escapes_untrusted_log_content():
    with TestClient(app) as client:
        login(client)
        response = client.post(
            "/api/logs",
            json={
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "203.0.113.77",
                "username": "<script>alert('xss')</script>",
                "event_type": "login",
                "status": "success",
                "country": "high-risk",
            },
        )
        assert response.status_code == 201
        alerts = client.get("/api/alerts?q=203.0.113.77").json()["items"]
        assert alerts
        report = client.get(f"/api/alerts/{alerts[0]['id']}/report")
        assert "<script>alert('xss')</script>" not in report.text
        assert "&lt;script&gt;" in report.text
