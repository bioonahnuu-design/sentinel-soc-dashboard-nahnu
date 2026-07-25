import argparse
import random
from datetime import datetime, timedelta, timezone

import httpx


IPS = ["103.12.44.19", "45.77.21.9", "185.220.101.5", "192.168.1.42", "10.10.0.18"]
USERS = ["admin", "nahnu", "analyst", "root", "guest", "service-account"]
COUNTRIES = ["Indonesia", "Singapore", "Germany", "Unknown", "United States"]


def main():
    parser = argparse.ArgumentParser(description="Generate demo authentication logs")
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--count", type=int, default=120)
    args = parser.parse_args()
    now = datetime.now(timezone.utc)

    with httpx.Client(base_url=args.url, timeout=10) as client:
        for index in range(args.count):
            source_ip = random.choice(IPS)
            # Ensure one attacker crosses the brute-force threshold.
            if index < 8:
                source_ip, status, username = "185.220.101.5", "failed", "admin"
                timestamp = now - timedelta(minutes=9 - index)
            else:
                status = random.choices(["success", "failed"], weights=[72, 28])[0]
                username = random.choice(USERS)
                timestamp = now - timedelta(minutes=random.randint(0, 1380))
            payload = {
                "timestamp": timestamp.isoformat(),
                "source_ip": source_ip,
                "username": username,
                "event_type": "login",
                "status": status,
                "user_agent": random.choice(["Mozilla/5.0", "curl/8.5", "python-httpx/0.28"]),
                "country": random.choice(COUNTRIES),
            }
            response = client.post("/api/logs", json=payload)
            response.raise_for_status()
    print(f"Created {args.count} demo events at {args.url}")


if __name__ == "__main__":
    main()

