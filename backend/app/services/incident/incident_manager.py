from datetime import datetime
import uuid


def create_incident(events):
    """
    Convert a correlated event cluster into a structured incident object.
    """

    if not events:
        return None

    # -------------------------------------------------
    # INCIDENT ID
    # -------------------------------------------------

    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

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
    # RISK
    # -------------------------------------------------

    risk_scores = [
        event.get("risk_score", 0)
        for event in sorted_events
    ]

    max_risk_score = max(risk_scores) if risk_scores else 0
    average_risk_score = (
        round(sum(risk_scores) / len(risk_scores), 2)
        if risk_scores
        else 0
    )

    # -------------------------------------------------
    # PRIORITY
    # -------------------------------------------------

    priorities = [
        event.get("priority")
        for event in sorted_events
        if event.get("priority")
    ]

    if "critical" in priorities:
        priority = "critical"
    elif "high" in priorities:
        priority = "high"
    elif "medium" in priorities:
        priority = "medium"
    else:
        priority = "low"

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
            "maximum": max_risk_score,
            "average": average_risk_score,
            "priority": priority
        },

        "timeline": sorted_events

    }

    return incident
    
def create_incidents(correlated_events):

    incidents = []

    for cluster in correlated_events:

        incident = create_incident(cluster)

        if incident:
            incidents.append(incident)

    return incidents
