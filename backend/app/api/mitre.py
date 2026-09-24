from fastapi import APIRouter

from app.services.wazuh.opensearch_client import fetch_logs
from app.services.classification.event_classifier import classify_event
from app.services.mitre.mitre_mapper import map_mitre_events


router = APIRouter()


@router.get("/mitre")
def get_mitre_mappings():

    # Get security events from Wazuh
    events = fetch_logs(50)

    # Classify the events first
    classified_events = []

    for event in events:

        classified_event = classify_event(
            event
        )

        classified_events.append(
            classified_event
        )

    # Map the events to MITRE ATT&CK
    mitre_results = map_mitre_events(
        classified_events
    )

    return {
        "event_count": len(mitre_results),
        "mitre_mappings": mitre_results
    }