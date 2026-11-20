import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import APIRouter
from backend_api.main import app as p3_backend_app

# The p3_backend_app contains Person 3's native tested endpoints matching frontend:
# /api/v1/advisory/generate
# /api/v1/correlation/analyze
# /api/v1/correlation/storyline
# /api/v1/threats/analyze-pcap
# /api/v1/threats/scan-url
# /api/v1/threats/scan-sms
# /api/v1/monitoring/start
# /api/v1/monitoring/stop
# /api/v1/monitoring/status
# /api/v1/monitoring/events
# /api/v1/assistant/query

router = APIRouter(tags=["Person 3 Direct Integration"])

for route in p3_backend_app.routes:
    if hasattr(route, "path") and route.path.startswith("/api/v1/"):
        if route.path != "/api/v1/health":
            router.routes.append(route)
