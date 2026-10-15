from fastapi import APIRouter

from app.services.wazuh.opensearch_client import fetch_logs
from app.services.classification.event_classifier import classify_event
from app.services.correlation.correlation_engine import (
    correlate_events,
    correlate_event_clusters,
    build_incident,
)
from app.services.incident.incident_manager import create_incidents
from fastapi import HTTPException
from app.services.explainability.llm_explainer import generate_llm_summary

router = APIRouter()


@router.get("/logs")
def get_logs():

    # Fetch the 2,000 most recent Wazuh alerts for live evaluation.
    events = fetch_logs(2000)

    classified_events = []

    for event in events:

        classified_event = classify_event(event)

        classified_events.append(
            classified_event
        )

    return classified_events


@router.get("/incidents")
def get_incidents():
    events = fetch_logs(2000)
    classified_events = [classify_event(event) for event in events]
    return correlate_events(classified_events)

@router.get("/incidents/{incident_id}")
def get_incident_details(incident_id: str):
    events = fetch_logs(2000)
    classified_events = [classify_event(event) for event in events]
    clusters = correlate_event_clusters(classified_events)

    for cluster in clusters:
        summary = build_incident(cluster)

        if summary and summary.get("incident_id") == incident_id:
            from app.services.incident.incident_manager import create_incident

            detailed_incident = create_incident(cluster)

            # Preserve the ID used by the dashboard's incident list.
            detailed_incident["incident_id"] = incident_id
            return detailed_incident

    raise HTTPException(status_code=404, detail="Incident not found")


@router.post("/incidents/{incident_id}/llm-explanation")
def get_incident_llm_explanation(incident_id: str):
    """
    Generate an on-demand AI explanation for one incident.

    Fetches and classifies recent logs, rebuilds correlated incidents,
    selects the requested incident, and asks the LLM to summarize its
    available evidence. It does not modify the incident's risk score.
    """
    # Fetch recent events from the existing Wazuh/OpenSearch integration.
    events = fetch_logs(50)

    # Classify each event before correlation.
    classified_events = [
        classify_event(event)
        for event in events
    ]

    # Group related events into incident clusters.
    correlated_clusters = correlate_events(classified_events)
    incidents = create_incidents(correlated_clusters)

    # Find only the incident requested by the analyst.
    incident = next(
        (
            item for item in incidents
            if item.get("incident_id") == incident_id
        ),
        None,
    )

    # Return a clear error if the incident is not in this result set.
    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found in the recent incident results.",
        )

    # Generate an evidence-grounded summary only for this incident.
    explanation = generate_llm_summary(incident)

    # Return the explanation separately from the existing risk assessment.
    return {
        "incident_id": incident_id,
        "llm_explanation": explanation,
    }

    