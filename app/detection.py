from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .models import Alert, SecurityLog


def detect_threats(db: Session, log: SecurityLog) -> list[Alert]:
    alerts: list[Alert] = []

    if log.event_type == "login" and log.status == "failed":
        window_start = log.timestamp - timedelta(minutes=settings.brute_force_window_minutes)
        failed_count = db.scalar(
            select(func.count(SecurityLog.id)).where(
                SecurityLog.source_ip == log.source_ip,
                SecurityLog.event_type == "login",
                SecurityLog.status == "failed",
                SecurityLog.timestamp >= window_start,
                SecurityLog.timestamp <= log.timestamp,
            )
        ) or 0

        if failed_count >= settings.brute_force_threshold:
            recent_duplicate = db.scalar(
                select(Alert).where(
                    Alert.source_ip == log.source_ip,
                    Alert.rule_name == "BRUTE_FORCE_LOGIN",
                    Alert.created_at >= window_start,
                )
            )
            if not recent_duplicate:
                alerts.append(
                    Alert(
                        log_id=log.id,
                        title="Possible brute-force attack",
                        description=(
                            f"{failed_count} failed login attempts from {log.source_ip} "
                            f"within {settings.brute_force_window_minutes} minutes."
                        ),
                        severity="high",
                        rule_name="BRUTE_FORCE_LOGIN",
                        source_ip=log.source_ip,
                    )
                )

    if log.status == "success" and log.country and log.country.lower() in {"unknown", "high-risk"}:
        alerts.append(
            Alert(
                log_id=log.id,
                title="Suspicious successful login",
                description=f"Successful login for {log.username} from a flagged location ({log.country}).",
                severity="medium",
                rule_name="SUSPICIOUS_LOCATION",
                source_ip=log.source_ip,
            )
        )

    db.add_all(alerts)
    return alerts

