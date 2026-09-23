from fastapi import APIRouter

from app.services.wazuh.opensearch_client import fetch_logs
from app.services.classification.event_classifier import classify_event
from app.services.anomaly.anomaly_detector import (
    annotate_events_with_anomalies,
)
from app.services.anomaly.isolation_forest_detector import (
    detect_isolation_forest_anomalies,
)

router = APIRouter()


@router.get("/anomalies")
def get_anomalies():
    events = fetch_logs(200)

    classified_events = [
        classify_event(event)
        for event in events
    ]

    # Existing explainable behavioral detection
    _, behavioral_anomalies = annotate_events_with_anomalies(
        classified_events
    )



    # Use chronological behavioral windows:
    # older 75% for training, newer 25% for detection
    from app.services.anomaly.isolation_forest_detector import (
        IsolationForestDetector,
    )

    detector = IsolationForestDetector()

    windows = detector._build_windows(classified_events)

    if len(windows) >= 4:
        split = len(windows) * 3 // 4

        training_events = [
            event
            for window in windows[:split]
            for event in window
        ]

        test_events = [
            event
            for window in windows[split:]
            for event in window
        ]

        ml_anomalies = detect_isolation_forest_anomalies(
    training_events,
    test_events,
     )
    else:
        ml_anomalies = []

    return {
    "summary": {
        "behavioral_count": len(behavioral_anomalies),
        "ml_anomalous_windows": sum(
            1 for item in ml_anomalies
            if item["is_anomaly"]
        ),
        "ml_total_windows": len(ml_anomalies),
    },
    "behavioral_anomalies": behavioral_anomalies,
    "isolation_forest_anomalies": ml_anomalies,
}