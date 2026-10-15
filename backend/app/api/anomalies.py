
"""API endpoint for behavioral and Isolation Forest anomaly detection."""

from fastapi import APIRouter

from app.services.wazuh.opensearch_client import fetch_logs
from app.services.classification.event_classifier import classify_event
from app.services.anomaly.anomaly_detector import (
    annotate_events_with_anomalies,
)
from app.services.anomaly.isolation_forest_detector import (
    IsolationForestDetector,
)
from app.services.explainability.shap_explainer import (
    explain_isolation_forest,
)

router = APIRouter()


@router.get("/anomalies")
def get_anomalies():
    """
    Detect behavioral anomalies and explain ML anomaly scores.

    Fetch recent events for the existing behavioral detector, then use
    older and newer historical windows to train and evaluate one
    Isolation Forest instance. SHAP explains selected windows using
    that same fitted model; it does not calculate a separate risk score.
    """
    # Preserve the existing behavioral detection on recent alerts.
    recent_events = [
        classify_event(event)
        for event in fetch_logs(200)
    ]

    _, behavioral_anomalies = annotate_events_with_anomalies(
        recent_events
    )

    # Fetch historical events to build the detector's five-minute windows.
    historical_events = [
        classify_event(event)
        for event in fetch_logs(6000)
    ]

    detector = IsolationForestDetector()
    windows = detector._build_windows(historical_events)

    ml_anomalies = []

    # Train on earlier windows and evaluate only later windows.
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

        # Fit once so anomaly scores and SHAP explanations use the same model.
        detector.fit(training_events)

        # Detect anomalies in the newer windows with the fitted detector.
        ml_anomalies = detector.detect(test_events)

        # Use a small background sample to limit SHAP computation time.
        training_features = detector.build_features(training_events)
        background_data = training_features[:10]

        # Explain only anomalous windows; ordinary windows need no SHAP call.
        for anomaly in ml_anomalies:
            if anomaly["is_anomaly"] and background_data:
                anomaly["shap_explanation"] = explain_isolation_forest(
                    model=detector.model,
                    feature_names=detector.FEATURE_NAMES,
                    feature_values=anomaly["features"],
                    background_data=background_data,
                )
            else:
                anomaly["shap_explanation"] = {
                    "available": False,
                    "reason": "SHAP is generated only for detected anomalies.",
                    "feature_contributions": [],
                }

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
