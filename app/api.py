import csv
import html
import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import ValidationError
from sqlalchemy import case, desc, func, or_, select
from sqlalchemy.orm import Session

from .database import get_db
from .detection import detect_threats
from .models import Alert, SecurityLog
from .schemas import AlertDetail, AlertOut, AlertPage, LogCreate, LogOut

router = APIRouter(prefix="/api")
ALLOWED_TIME_RANGES = {1, 24, 168, 720}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_UPLOAD_RECORDS = 1000


def range_start(hours: int) -> datetime:
    if hours not in ALLOWED_TIME_RANGES:
        raise HTTPException(
            status_code=422,
            detail="hours must be one of: 1, 24, 168, 720",
        )
    return datetime.now(timezone.utc) - timedelta(hours=hours)


def log_search_filter(query: str | None):
    if not query or not query.strip():
        return None
    pattern = f"%{query.strip()}%"
    return or_(
        SecurityLog.source_ip.ilike(pattern),
        SecurityLog.username.ilike(pattern),
    )


def alert_search_filter(query: str | None):
    if not query or not query.strip():
        return None
    pattern = f"%{query.strip()}%"
    return or_(
        Alert.source_ip.ilike(pattern),
        SecurityLog.username.ilike(pattern),
    )


@router.post("/logs", response_model=LogOut, status_code=201)
def ingest_log(payload: LogCreate, db: Session = Depends(get_db)):
    log = SecurityLog(**payload.model_dump())
    db.add(log)
    db.flush()
    detect_threats(db, log)
    db.commit()
    db.refresh(log)
    return log


def parse_uploaded_records(filename: str, content: bytes) -> tuple[str, list[dict]]:
    extension = Path(filename).suffix.lower()
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(422, "File must use UTF-8 encoding") from exc

    if extension == ".csv":
        try:
            records = list(csv.DictReader(io.StringIO(text)))
        except csv.Error as exc:
            raise HTTPException(422, f"Invalid CSV file: {exc}") from exc
        file_format = "csv"
    elif extension == ".json":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise HTTPException(422, f"Invalid JSON file at line {exc.lineno}") from exc
        if isinstance(parsed, dict):
            parsed = parsed.get("logs")
        if not isinstance(parsed, list):
            raise HTTPException(422, 'JSON must be an array or an object containing a "logs" array')
        records = parsed
        file_format = "json"
    else:
        raise HTTPException(415, "Only .csv and .json files are supported")

    if not records:
        raise HTTPException(422, "The uploaded file contains no log records")
    if len(records) > MAX_UPLOAD_RECORDS:
        raise HTTPException(413, f"A maximum of {MAX_UPLOAD_RECORDS} records is allowed per upload")
    if not all(isinstance(record, dict) for record in records):
        raise HTTPException(422, "Every log record must be an object")
    return file_format, records


@router.post("/logs/upload")
async def upload_logs(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    filename = file.filename or "upload"
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File is larger than the 2 MB upload limit")

    file_format, records = parse_uploaded_records(filename, content)
    valid_logs: list[LogCreate] = []
    errors: list[dict] = []
    for index, record in enumerate(records, start=2 if file_format == "csv" else 1):
        cleaned = {key: value for key, value in record.items() if value not in ("", None)}
        try:
            valid_logs.append(LogCreate.model_validate(cleaned))
        except ValidationError as exc:
            message = "; ".join(
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                for error in exc.errors()
            )
            errors.append({"record": index, "message": message})

    if not valid_logs:
        raise HTTPException(
            422,
            {"message": "No valid log records were found", "errors": errors[:20]},
        )

    alerts_created = 0
    try:
        for payload in valid_logs:
            log = SecurityLog(**payload.model_dump())
            db.add(log)
            db.flush()
            alerts_created += len(detect_threats(db, log))
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "filename": filename,
        "format": file_format,
        "imported": len(valid_logs),
        "rejected": len(errors),
        "alerts_created": alerts_created,
        "errors": errors[:20],
    }


@router.get("/logs", response_model=list[LogOut])
def list_logs(
    limit: int = Query(50, ge=1, le=200),
    hours: int = Query(24),
    q: str | None = Query(None, max_length=100),
    status: str | None = Query(None),
    db: Session = Depends(get_db),
):
    filters = [SecurityLog.timestamp >= range_start(hours)]
    if status:
        normalized_status = status.lower().strip()
        if normalized_status not in {"success", "failed"}:
            raise HTTPException(status_code=422, detail="status must be success or failed")
        filters.append(SecurityLog.status == normalized_status)
    search_filter = log_search_filter(q)
    if search_filter is not None:
        filters.append(search_filter)
    return list(
        db.scalars(
            select(SecurityLog)
            .where(*filters)
            .order_by(desc(SecurityLog.timestamp))
            .limit(limit)
        )
    )


@router.get("/alerts", response_model=AlertPage)
def list_alerts(
    severity: str | None = None,
    acknowledged: bool | None = None,
    hours: int = Query(24),
    q: str | None = Query(None, max_length=100),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    filters = [Alert.created_at >= range_start(hours)]
    if severity:
        normalized_severity = severity.lower().strip()
        if normalized_severity not in {"high", "medium", "low"}:
            raise HTTPException(status_code=422, detail="severity must be high, medium, or low")
        filters.append(Alert.severity == normalized_severity)
    if acknowledged is not None:
        filters.append(Alert.acknowledged == acknowledged)
    search_filter = alert_search_filter(q)
    if search_filter is not None:
        filters.append(search_filter)
    count_query = select(func.count(Alert.id)).outerjoin(SecurityLog, Alert.log_id == SecurityLog.id).where(*filters)
    total = db.scalar(count_query) or 0
    items = list(
        db.scalars(
            select(Alert)
            .outerjoin(SecurityLog, Alert.log_id == SecurityLog.id)
            .where(*filters)
            .order_by(desc(Alert.created_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    return AlertPage(items=items, total=total, page=page, page_size=page_size)


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return {
        "id": alert.id,
        "incident_id": f"INC-{alert.id:06d}",
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "rule_name": alert.rule_name,
        "source_ip": alert.source_ip,
        "acknowledged": alert.acknowledged,
        "created_at": alert.created_at,
        "log": alert.log,
    }


@router.get("/alerts/{alert_id}/report", response_class=HTMLResponse)
def incident_report(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")

    incident_id = f"INC-{alert.id:06d}"
    log = alert.log
    generated_at = datetime.now(timezone.utc)

    def safe(value) -> str:
        return html.escape(str(value if value not in (None, "") else "—"))

    raw_log = {
        "id": log.id,
        "timestamp": log.timestamp.isoformat(),
        "source_ip": log.source_ip,
        "username": log.username,
        "event_type": log.event_type,
        "status": log.status,
        "user_agent": log.user_agent,
        "country": log.country,
    } if log else {"message": "No source log attached"}
    raw_json = html.escape(json.dumps(raw_log, indent=2))
    status = "Acknowledged" if alert.acknowledged else "Open"

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{safe(incident_id)} Incident Report</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ color:#172033; font:14px Arial,sans-serif; margin:0; background:#eef2f7; }}
    .page {{ background:white; margin:28px auto; max-width:900px; min-height:1100px; padding:48px; box-shadow:0 12px 35px #14213d22; }}
    header {{ border-bottom:3px solid #0ea5c6; display:flex; justify-content:space-between; padding-bottom:22px; }}
    .brand {{ color:#0b7285; font-size:12px; font-weight:700; letter-spacing:2px; }}
    h1 {{ font-size:28px; margin:8px 0 0; }}
    .meta {{ color:#607087; font-size:12px; line-height:1.6; text-align:right; }}
    .status {{ display:flex; gap:10px; margin:25px 0; }}
    .pill {{ border-radius:20px; font-size:11px; font-weight:700; padding:7px 12px; text-transform:uppercase; }}
    .severity {{ background:#fff2cf; color:#995d00; }}
    .state {{ background:#e2f7ec; color:#087443; }}
    .summary {{ background:#f5f8fc; border-left:4px solid #0ea5c6; line-height:1.7; padding:18px; }}
    h2 {{ border-bottom:1px solid #dae2ec; font-size:16px; margin:28px 0 14px; padding-bottom:9px; }}
    .grid {{ display:grid; gap:12px; grid-template-columns:repeat(3,1fr); }}
    .field {{ border:1px solid #dae2ec; border-radius:7px; min-height:74px; padding:12px; }}
    .field span {{ color:#718096; display:block; font-size:9px; letter-spacing:1px; margin-bottom:8px; text-transform:uppercase; }}
    .field strong {{ overflow-wrap:anywhere; }}
    pre {{ background:#0a1220; border-radius:8px; color:#c5d6e8; font-size:11px; line-height:1.5; overflow-wrap:anywhere; padding:18px; white-space:pre-wrap; }}
    footer {{ border-top:1px solid #dae2ec; color:#718096; font-size:10px; line-height:1.5; margin-top:32px; padding-top:16px; }}
    .actions {{ position:fixed; right:24px; top:24px; }}
    button {{ background:#0ea5c6; border:0; border-radius:7px; color:white; cursor:pointer; font-weight:700; padding:11px 16px; }}
    @media print {{
      body {{ background:white; }}
      .page {{ box-shadow:none; margin:0; max-width:none; min-height:auto; padding:20mm; }}
      .actions {{ display:none; }}
    }}
    @media(max-width:700px) {{ .page {{ margin:0; padding:24px; }} .grid {{ grid-template-columns:1fr 1fr; }} }}
  </style>
</head>
<body>
  <div class="actions"><button onclick="window.print()">Print / Save as PDF</button></div>
  <article class="page">
    <header>
      <div><div class="brand">SENTINEL SECURITY OPERATIONS CENTER</div><h1>Incident Report</h1></div>
      <div class="meta"><strong>{safe(incident_id)}</strong><br>Generated {safe(generated_at.strftime("%Y-%m-%d %H:%M UTC"))}</div>
    </header>
    <div class="status"><span class="pill severity">{safe(alert.severity)}</span><span class="pill state">{safe(status)}</span></div>
    <h2>{safe(alert.title)}</h2>
    <div class="summary">{safe(alert.description)}</div>
    <h2>Detection Context</h2>
    <div class="grid">
      <div class="field"><span>Incident ID</span><strong>{safe(incident_id)}</strong></div>
      <div class="field"><span>Detection Rule</span><strong>{safe(alert.rule_name)}</strong></div>
      <div class="field"><span>Detected At</span><strong>{safe(alert.created_at)}</strong></div>
      <div class="field"><span>Source IP</span><strong>{safe(alert.source_ip)}</strong></div>
      <div class="field"><span>Username</span><strong>{safe(log.username if log else None)}</strong></div>
      <div class="field"><span>Event / Result</span><strong>{safe(f"{log.event_type} / {log.status}" if log else None)}</strong></div>
      <div class="field"><span>Country</span><strong>{safe(log.country if log else None)}</strong></div>
      <div class="field"><span>User Agent</span><strong>{safe(log.user_agent if log else None)}</strong></div>
      <div class="field"><span>Analyst Status</span><strong>{safe(status)}</strong></div>
    </div>
    <h2>Raw Source Log</h2>
    <pre>{raw_json}</pre>
    <footer>This report was generated by Sentinel SOC Dashboard for defensive security monitoring and incident documentation. Validate findings before taking operational action.</footer>
  </article>
</body>
</html>"""
    return HTMLResponse(
        content=document,
        headers={"Content-Disposition": f'inline; filename="{incident_id}-report.html"'},
    )


@router.patch("/alerts/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.acknowledged = True
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/stats/overview")
def overview(
    hours: int = Query(24),
    q: str | None = Query(None, max_length=100),
    db: Session = Depends(get_db),
):
    since = range_start(hours)
    log_filters = [SecurityLog.timestamp >= since]
    search_filter = log_search_filter(q)
    if search_filter is not None:
        log_filters.append(search_filter)
    row = db.execute(
        select(
            func.count(SecurityLog.id),
            func.sum(case((SecurityLog.status == "failed", 1), else_=0)),
            func.count(func.distinct(SecurityLog.source_ip)),
        ).where(*log_filters)
    ).one()
    alert_filters = [Alert.acknowledged.is_(False), Alert.created_at >= since]
    alert_query_filter = alert_search_filter(q)
    if alert_query_filter is not None:
        alert_filters.append(alert_query_filter)
    active_alerts = db.scalar(
        select(func.count(Alert.id))
        .outerjoin(SecurityLog, Alert.log_id == SecurityLog.id)
        .where(*alert_filters)
    ) or 0
    return {
        "total_events": row[0] or 0,
        "failed_logins": row[1] or 0,
        "unique_ips": row[2] or 0,
        "active_alerts": active_alerts,
    }


@router.get("/stats/timeline")
def timeline(
    hours: int = Query(24),
    q: str | None = Query(None, max_length=100),
    db: Session = Depends(get_db),
):
    since = range_start(hours)
    unit = "minute" if hours == 1 else "hour" if hours == 24 else "day"
    bucket = func.date_trunc(unit, SecurityLog.timestamp)
    if db.bind and db.bind.dialect.name == "sqlite":
        sqlite_format = "%Y-%m-%d %H:%M:00" if hours == 1 else "%Y-%m-%d %H:00:00" if hours == 24 else "%Y-%m-%d 00:00:00"
        bucket = func.strftime(sqlite_format, SecurityLog.timestamp)
    filters = [SecurityLog.timestamp >= since]
    search_filter = log_search_filter(q)
    if search_filter is not None:
        filters.append(search_filter)
    rows = db.execute(
        select(
            bucket.label("hour"),
            func.count(SecurityLog.id).label("total"),
            func.sum(case((SecurityLog.status == "failed", 1), else_=0)).label("failed"),
        )
        .where(*filters)
        .group_by(bucket)
        .order_by(bucket)
    ).all()
    return [{"hour": str(r.hour), "total": r.total, "failed": r.failed or 0} for r in rows]


@router.get("/stats/top-ips")
def top_ips(
    hours: int = Query(24),
    q: str | None = Query(None, max_length=100),
    db: Session = Depends(get_db),
):
    filters = [
        SecurityLog.status == "failed",
        SecurityLog.timestamp >= range_start(hours),
    ]
    search_filter = log_search_filter(q)
    if search_filter is not None:
        filters.append(search_filter)
    rows = db.execute(
        select(SecurityLog.source_ip, func.count(SecurityLog.id).label("count"))
        .where(*filters)
        .group_by(SecurityLog.source_ip)
        .order_by(desc("count"))
        .limit(5)
    ).all()
    return [{"ip": r.source_ip, "count": r.count} for r in rows]
