from fastapi import APIRouter

from app.services.wazuh.opensearch_client import fetch_logs
from app.services.classification.event_classifier import classify_event
from app.services.correlation.correlation_engine import correlate_events


router = APIRouter()


@router.get("/logs")
def get_logs():

    events = fetch_logs(50)

    classified_events = []

    for event in events:

        classified_event = classify_event(event)

        classified_events.append(
            classified_event
        )

    return classified_events


@router.get("/incidents")
def get_incidents():

    events = fetch_logs(50)

    classified_events = []

    for event in events:

        classified_event = classify_event(event)

        classified_events.append(
            classified_event
        )

    incidents = correlate_events(
        classified_events
    )

    return incidents