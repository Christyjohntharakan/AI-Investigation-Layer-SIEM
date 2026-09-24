from fastapi import APIRouter

from app.services.wazuh.opensearch_client import fetch_logs
from app.services.classification.event_classifier import classify_event
from app.services.correlation.correlation_engine import correlate_events
from app.services.timeline.timeline_reconstructor import (
    reconstruct_timeline
)


router = APIRouter()


@router.get("/timeline")
def get_timeline():

    # Get security logs from Wazuh
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

    # Group related events into incidents
    incidents = correlate_events(
        classified_events
    )

    timelines = []

    # Reconstruct timeline for each incident
    for incident in incidents:

        timeline = reconstruct_timeline(
            incident.get("events", [])
        )

        timelines.append({

            "incident_id":
                incident.get("incident_id"),

            "agent_id":
                incident.get("agent_id"),

            "agent_name":
                incident.get("agent_name"),

            "priority":
                incident.get("priority"),

            "max_risk_score":
                incident.get(
                    "max_risk_score",
                    0
                ),

            "timeline":
                timeline

        })

    return timelines