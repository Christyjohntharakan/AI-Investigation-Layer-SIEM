import hashlib
import json
from app.services.timeline.timeline_engine import reconstruct_timeline
from app.services.mitre.mitre_mapper import map_mitre
from app.services.risk.risk_engine import calculate_incident_risk
from app.services.memory.memory_engine import investigation_memory
from app.services.explainability.llm_explainer import generate_llm_summary
from app.services.explainability.explainability_engine import generate_explanation
from app.services.decision.decision_engine import generate_decision
from app.services.recommendation.recommendation_engine import generate_recommendations

def create_incident(events):
    """
    Convert a correlated event cluster into a structured incident object.
    """

    if not events:
        return None

    # -------------------------------------------------
    # INCIDENT ID
    # -------------------------------------------------

    # Generate a stable ID from the incident's actual events.
    # This prevents the same Wazuh events from becoming a new
    # incident every time /incidents is requested.
    fingerprint_data = []
    for event in events:
        fingerprint_data.append({
        "timestamp": event.get("timestamp"),
        "agent_name": event.get("agent_name"),
        "category": event.get("category"),
        "description": event.get("description"),
        "source_ip": event.get("source_ip"),
        "destination_ip": event.get("destination_ip"),
        "source_user": event.get("source_user"),
        "destination_user": event.get("destination_user"),
        "mitre_techniques": sorted(event.get("mitre_techniques", [])),
    })
    
    fingerprint_text = json.dumps(
    sorted(
        fingerprint_data,
        key=lambda event: (
            event.get("timestamp") or "",
            event.get("description") or ""
        )
    ),
    sort_keys=True
    )
    fingerprint = hashlib.sha256(fingerprint_text.encode("utf-8")
    ).hexdigest()
    
    incident_id = f"INC-{fingerprint[:12].upper()}"

    # -------------------------------------------------
    # SORT EVENTS BY TIME
    # -------------------------------------------------

    sorted_events = sorted(
        events,
        key=lambda event: event.get("timestamp") or ""
    )

    # -------------------------------------------------
    # BASIC INFORMATION
    # -------------------------------------------------

    timestamps = [
        event.get("timestamp")
        for event in sorted_events
        if event.get("timestamp")
    ]

    first_seen = timestamps[0] if timestamps else None
    last_seen = timestamps[-1] if timestamps else None

    # -------------------------------------------------
    # AGENT
    # -------------------------------------------------

    agents = list({
        event.get("agent_name")
        for event in sorted_events
        if event.get("agent_name")
    })

    # -------------------------------------------------
    # USERS
    # -------------------------------------------------

    users = set()

    for event in sorted_events:

        source_user = event.get("source_user")
        destination_user = event.get("destination_user")

        if source_user:
            users.add(source_user)

        if destination_user:
            users.add(destination_user)

    # -------------------------------------------------
    # CATEGORIES
    # -------------------------------------------------

    categories = list({
        event.get("category")
        for event in sorted_events
        if event.get("category")
    })

    # -------------------------------------------------
    # MITRE ATT&CK
    # -------------------------------------------------

    mitre_techniques = set()
    mitre_tactics = set()

    for event in sorted_events:

        mitre_techniques.update(
            event.get("mitre_techniques", [])
        )

        mitre_tactics.update(
            event.get("mitre_tactics", [])
        )

    # -------------------------------------------------
    # RISK INTELLIGENCE
    # -------------------------------------------------
    risk_analysis = calculate_incident_risk(sorted_events)
    risk_score = risk_analysis["risk_score"]
    priority = risk_analysis["priority"]
    risk_explanation = risk_analysis["risk_explanation"]

    explainability = generate_explanation({
    "risk": {
        "score": risk_score,
        "priority": priority,
        "explanation": risk_explanation
    }
    })
    risk_scores = [event.get("risk_score", 0) for event in sorted_events]
    max_risk_score = max(risk_scores) if risk_scores else 0
    average_event_risk = (
        round(sum(risk_scores) / len(risk_scores), 2)
        if risk_scores
        else 0
    )

    # -------------------------------------------------
    # INCIDENT SUMMARY
    # -------------------------------------------------

    summary = (
        f"Incident involving {len(sorted_events)} correlated "
        f"security events"
    )

    # -------------------------------------------------
    # CREATE INCIDENT OBJECT
    # -------------------------------------------------

    incident = {

        "incident_id": incident_id,

        "status": "open",

        "summary": summary,

        "first_seen": first_seen,

        "last_seen": last_seen,

        "event_count": len(sorted_events),
               
        "events": sorted_events,

        "agents": agents,

        "users": list(users),

        "categories": categories,

        "mitre_techniques": sorted(
            mitre_techniques
        ),

        "mitre_tactics": sorted(
            mitre_tactics
        ),
        "risk": {
            "score": risk_score,
            "maximum_event_risk": max_risk_score,
            "average_event_risk": average_event_risk,
            "priority": priority,
            "explanation": risk_explanation
        },
        "explainability": explainability,
        "mitre": map_mitre(sorted_events),
        "timeline": reconstruct_timeline(sorted_events)

    }
    # -------------------------------------------------
    # INVESTIGATION MEMORY
    # -------------------------------------------------

    similar_incidents = investigation_memory.find_similar_incidents(
        incident,
        limit=3
    )

    incident["investigation_memory"] = {
        "similar_incidents": similar_incidents
    }
    decision = generate_decision(incident)
    incident["decision_intelligence"] = decision

    recommendations = generate_recommendations(incident)
    incident["recommendations"] = recommendations


    # Keep LLM generation out of incident creation.
    # The explanation will be generated only when an analyst requests it.
    incident["llm_explanation"] = {
        "available": False,
        "model": "qwen2.5:1.5b",
        "summary": "",
        "reason": "Not generated yet. Request an explanation when needed.",
    }

    # Store current incident for future investigations.
    investigation_memory.store_incident(incident)

    return incident

    
def create_incidents(correlated_events):
    """
    Create structured incident objects from correlated event clusters.
    Duplicate incident IDs are removed to prevent the same
    incident from appearing multiple times.
    """

    incidents = []
    seen_incident_ids = set()

    for cluster in correlated_events:
        incident = create_incident(cluster)

        if not incident:
            continue

        incident_id = incident.get("incident_id")

        if incident_id in seen_incident_ids:
            continue

        seen_incident_ids.add(incident_id)
        incidents.append(incident)

    return incidents