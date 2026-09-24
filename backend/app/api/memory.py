from fastapi import APIRouter

from app.services.wazuh.opensearch_client import fetch_logs
from app.services.classification.event_classifier import classify_event
from app.services.correlation.correlation_engine import correlate_events
from app.services.mitre.mitre_mapper import map_mitre_events
from app.services.mitre.securebert_mapper import encode_security_event

from app.services.memory.incident_memory import (
    store_incident,
    find_similar_incidents
)


router = APIRouter()


@router.get("/memory")
def get_investigation_memory():

    # Get security events from Wazuh
    events = fetch_logs(50)

    # Classify events
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

    memory_results = []

    for incident in incidents:

        incident_id = incident.get(
            "incident_id"
        )

        # Create a SecureBERT embedding
        # for the incident
        embedding_result = encode_security_event(
            incident
        )

        embedding = embedding_result[
            "embedding"
        ]

        # Store the current incident
        # in Qdrant
        store_result = store_incident(
            incident_id=incident_id,
            embedding=embedding,
            incident=incident
        )

        # Search for similar previous incidents
        similar_incidents = find_similar_incidents(
            embedding=embedding,
            limit=5
        )

        memory_results.append({

            "incident_id":
                incident_id,

            "max_risk_score":
                incident.get(
                    "max_risk_score",
                    0
                ),

            "priority":
                incident.get(
                    "priority"
                ),

            "event_count":
                len(
                    incident.get(
                        "events",
                        []
                    )
                ),

            "stored_in_memory":
                store_result["stored"],

            "similar_incidents":
                similar_incidents
        })

    return {

        "incident_count":
            len(memory_results),

        "memory_results":
            memory_results
    }