from fastapi import APIRouter

from app.services.wazuh.opensearch_client import fetch_logs
from app.services.classification.event_classifier import classify_event
from app.services.anomaly.anomaly_detector import (
    annotate_events_with_anomalies,
)


# ============================================================
# NOTE FOR CHRISTY (integration owner):
#
# This router is self-contained and not wired into main.py yet,
# so it does not touch the dashboard/integration module. To
# enable it, add to backend/app/main.py:
#
#     from app.api.anomalies import router as anomaly_router
#     app.include_router(anomaly_router)
#
# It mirrors the existing /logs and /incidents pattern in
# api/logs.py.
# ============================================================


router = APIRouter()


@router.get("/anomalies")
def get_anomalies():
    """
    Fetch recent events, classify them, and return any
    behavioral anomalies detected across the batch.
    """

    events = fetch_logs(200)

    classified_events = [
        classify_event(event) for event in events
    ]

    _, anomalies = annotate_events_with_anomalies(classified_events)

    return anomalies
