from fastapi import APIRouter

from app.services.wazuh.opensearch_client import fetch_logs
from app.services.classification.event_classifier import classify_event
from app.services.explainability.explainability_engine import (
    explain_events
)


router = APIRouter()


@router.get("/explainability")
def get_explanations():

    # Get security events from Wazuh
    events = fetch_logs(50)

    # Classify the events
    classified_events = []

    for event in events:

        classified_event = classify_event(
            event
        )

        classified_events.append(
            classified_event
        )

    # Generate explanations
    explanations = explain_events(
        classified_events
    )

    return {
        "event_count":
            len(explanations),

        "explanations":
            explanations
    }