import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite:///./test_soc.db"

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.detection import detect_threats  # noqa: E402
from app.models import Alert, SecurityLog  # noqa: E402


def setup_function():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)


def test_brute_force_rule_creates_one_alert():
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    for i in range(5):
        log = SecurityLog(timestamp=now + timedelta(seconds=i), source_ip="1.2.3.4", username="admin", event_type="login", status="failed")
        db.add(log)
        db.flush()
        detect_threats(db, log)
    db.commit()
    assert db.query(Alert).count() == 1
    assert db.query(Alert).one().severity == "high"
    db.close()

