from datetime import datetime


CORRELATION_WINDOW_SECONDS = 60


# =========================================================
# TIMESTAMP PARSER
# =========================================================

def parse_timestamp(timestamp):
    """
    Convert an ISO timestamp into a datetime object.
    """

    if not timestamp:
        return None

    try:
        return datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

    except (ValueError, TypeError):
        return None


# =========================================================
# USER EXTRACTION
# =========================================================

def get_event_user(event):
    """
    Return the most relevant user associated with an event.
    """

    return (
        event.get("source_user")
        or event.get("destination_user")
    )


# =========================================================
# EVENT CORRELATION
# =========================================================

def events_are_related(event1, event2):
    """
    Determine whether two security events are related.

    Correlation considers:

    1. Same agent
    2. Time proximity
    3. Same user
    4. Same category
    5. Shared MITRE ATT&CK technique
    """

    # -----------------------------------------------------
    # 1. SAME AGENT
    # -----------------------------------------------------

    if event1.get("agent_id") != event2.get("agent_id"):
        return False

    # -----------------------------------------------------
    # 2. TIME WINDOW
    # -----------------------------------------------------

    time1 = parse_timestamp(
        event1.get("timestamp")
    )

    time2 = parse_timestamp(
        event2.get("timestamp")
    )

    if not time1 or not time2:
        return False

    time_difference = abs(
        (time1 - time2).total_seconds()
    )

    if time_difference > CORRELATION_WINDOW_SECONDS:
        return False

    # -----------------------------------------------------
    # 3. SAME USER
    # -----------------------------------------------------

    user1 = get_event_user(event1)
    user2 = get_event_user(event2)

    same_user = (
        user1 is not None
        and user2 is not None
        and user1 == user2
    )

    # -----------------------------------------------------
    # 4. SAME CATEGORY
    # -----------------------------------------------------

    category1 = event1.get("category")
    category2 = event2.get("category")

    same_category = (
        category1 is not None
        and category1 == category2
    )

    # -----------------------------------------------------
    # 5. SHARED MITRE TECHNIQUE
    # -----------------------------------------------------

    techniques1 = set(
        event1.get("mitre_techniques", [])
    )

    techniques2 = set(
        event2.get("mitre_techniques", [])
    )

    shared_techniques = techniques1.intersection(
        techniques2
    )

    shared_mitre = bool(shared_techniques)

    # -----------------------------------------------------
    # CORRELATION DECISION
    # -----------------------------------------------------

    # Strongest relationship:
    # both events share a MITRE technique.
    if shared_mitre:
        return True

    # Same user performing the same type of activity.
    if same_user and same_category:
        return True

    # Authentication + same user can represent
    # one continuous authentication activity.
    if same_user and (
        category1 == "authentication"
        or category2 == "authentication"
    ):
        return True

    return False


# =========================================================
# CORRELATION SCORE
# =========================================================

def calculate_correlation_score(event1, event2):
    """
    Calculate an explainable correlation score.

    Score components:

    Same agent       -> 20
    Time <= 10 sec   -> 30
    Time <= 30 sec   -> 20
    Time <= 60 sec   -> 10
    Same user        -> 20
    Same category    -> 15
    Shared MITRE     -> 25

    Maximum score is capped at 100.
    """

    score = 0
    reasons = []

    # -----------------------------------------------------
    # SAME AGENT
    # -----------------------------------------------------

    if event1.get("agent_id") == event2.get("agent_id"):

        score += 20

        reasons.append(
            "Events originated from the same agent."
        )

    # -----------------------------------------------------
    # TIME PROXIMITY
    # -----------------------------------------------------

    time1 = parse_timestamp(
        event1.get("timestamp")
    )

    time2 = parse_timestamp(
        event2.get("timestamp")
    )

    if time1 and time2:

        difference = abs(
            (time1 - time2).total_seconds()
        )

        if difference <= 10:

            score += 30

            reasons.append(
                "Events occurred within 10 seconds."
            )

        elif difference <= 30:

            score += 20

            reasons.append(
                "Events occurred within 30 seconds."
            )

        elif difference <= 60:

            score += 10

            reasons.append(
                "Events occurred within the "
                "60-second correlation window."
            )

    # -----------------------------------------------------
    # SAME USER
    # -----------------------------------------------------

    user1 = get_event_user(event1)
    user2 = get_event_user(event2)

    if user1 and user2 and user1 == user2:

        score += 20

        reasons.append(
            f"Both events are associated with "
            f"user '{user1}'."
        )

    # -----------------------------------------------------
    # SAME CATEGORY
    # -----------------------------------------------------

    category1 = event1.get("category")
    category2 = event2.get("category")

    if category1 and category1 == category2:

        score += 15

        reasons.append(
            f"Both events belong to the "
            f"'{category1}' category."
        )

    # -----------------------------------------------------
    # SHARED MITRE
    # -----------------------------------------------------

    techniques1 = set(
        event1.get("mitre_techniques", [])
    )

    techniques2 = set(
        event2.get("mitre_techniques", [])
    )

    shared = techniques1.intersection(
        techniques2
    )

    if shared:

        score += 25

        reasons.append(
            "Events share MITRE ATT&CK "
            "technique(s): "
            + ", ".join(sorted(shared))
        )

    return {
        "score": min(score, 100),
        "reasons": reasons
    }


# =========================================================
# INCIDENT RISK EXPLANATION
# =========================================================

def build_incident_risk_explanation(
    cluster,
    max_risk
):
    """
    Generate an explainable incident-level
    risk explanation.
    """

    factors = []

    # -----------------------------------------------------
    # 1. HIGHEST EVENT RISK
    # -----------------------------------------------------

    highest_event = max(
        cluster,
        key=lambda event: event.get(
            "risk_score",
            0
        )
    )

    highest_event_score = highest_event.get(
        "risk_score",
        0
    )

    factors.append(
        {
            "factor": "Highest event risk",
            "value": highest_event_score,
            "contribution": highest_event_score,
            "reason": (
                "The incident inherits the highest "
                "risk score among its correlated "
                "security events."
            )
        }
    )

    # -----------------------------------------------------
    # 2. CORRELATED EVENT COUNT
    # -----------------------------------------------------

    event_count = len(cluster)

    if event_count > 1:

        factors.append(
            {
                "factor": "Correlated event count",
                "value": event_count,
                "contribution": min(
                    event_count * 5,
                    20
                ),
                "reason": (
                    f"The incident contains "
                    f"{event_count} correlated events, "
                    "indicating repeated or related "
                    "security activity."
                )
            }
        )

    # -----------------------------------------------------
    # 3. MITRE TECHNIQUES
    # -----------------------------------------------------

    techniques = set()

    for event in cluster:

        techniques.update(
            event.get(
                "mitre_techniques",
                []
            )
        )

    if techniques:

        factors.append(
            {
                "factor": "MITRE ATT&CK techniques",
                "value": sorted(techniques),
                "contribution": min(
                    len(techniques) * 5,
                    15
                ),
                "reason": (
                    "The incident contains events "
                    "mapped to MITRE ATT&CK techniques, "
                    "indicating attacker-relevant "
                    "behavior."
                )
            }
        )

    # -----------------------------------------------------
    # 4. PRIORITY SUMMARY
    # -----------------------------------------------------

    if max_risk >= 70:

        summary = (
            "High-risk incident requiring "
            "prompt investigation."
        )

    elif max_risk >= 40:

        summary = (
            "Medium-risk incident containing "
            "security-relevant correlated activity."
        )

    else:

        summary = (
            "Low-risk incident with limited "
            "immediate security impact."
        )

    return {
        "summary": summary,
        "factors": factors
    }


# =========================================================
# BUILD INCIDENT
# =========================================================

def build_incident(cluster):
    """
    Convert a correlated event cluster
    into an incident object.
    """

    if not cluster:
        return None

    # -----------------------------------------------------
    # TIMELINE
    # -----------------------------------------------------

    timestamps = []

    for event in cluster:

        timestamp = parse_timestamp(
            event.get("timestamp")
        )

        if timestamp:
            timestamps.append(timestamp)

    if timestamps:

        first_seen = min(
            timestamps
        ).isoformat()

        last_seen = max(
            timestamps
        ).isoformat()

    else:

        first_seen = None
        last_seen = None

    # -----------------------------------------------------
    # MITRE INFORMATION
    # -----------------------------------------------------

    techniques = set()
    tactics = set()

    for event in cluster:

        techniques.update(
            event.get(
                "mitre_techniques",
                []
            )
        )

        tactics.update(
            event.get(
                "mitre_tactics",
                []
            )
        )

    # -----------------------------------------------------
    # MAX EVENT RISK
    # -----------------------------------------------------

    risk_scores = []

    for event in cluster:

        risk_scores.append(
            event.get(
                "risk_score",
                0
            )
        )

    max_risk = (
        max(risk_scores)
        if risk_scores
        else 0
    )

    # -----------------------------------------------------
    # PRIORITY
    # -----------------------------------------------------

    if max_risk >= 70:

        priority = "high"

    elif max_risk >= 40:

        priority = "medium"

    else:

        priority = "low"

    # -----------------------------------------------------
    # INCIDENT RISK EXPLANATION
    # -----------------------------------------------------

    risk_explanation = build_incident_risk_explanation(
        cluster,
        max_risk
    )

    # -----------------------------------------------------
    # INCIDENT OBJECT
    # -----------------------------------------------------

    return {
        "incident_id": f"INC-{id(cluster)}",

        "event_count": len(cluster),

        "first_seen": first_seen,

        "last_seen": last_seen,

        "agent_id": cluster[0].get(
            "agent_id"
        ),

        "agent_name": cluster[0].get(
            "agent_name"
        ),

        "max_risk_score": max_risk,

        "priority": priority,

        "mitre_techniques": sorted(
            techniques
        ),

        "mitre_tactics": sorted(
            tactics
        ),

        "risk_explanation": risk_explanation,

        "events": cluster
    }


# =========================================================
# CORRELATE EVENTS
# =========================================================

def correlate_events(events):
    """
    Group related security events into incidents.

    Uses connected-component style clustering.

    Example:

        Event A -> Event B -> Event C

    remains one incident even when A and C
    are not directly related.
    """

    incidents = []
    visited = set()

    # -----------------------------------------------------
    # FIND CONNECTED COMPONENTS
    # -----------------------------------------------------

    for i in range(len(events)):

        if i in visited:
            continue

        cluster_indices = {i}
        queue = [i]

        visited.add(i)

        while queue:

            current_index = queue.pop(0)

            current_event = events[
                current_index
            ]

            for j in range(len(events)):

                if j in visited:
                    continue

                candidate = events[j]

                if events_are_related(
                    current_event,
                    candidate
                ):

                    cluster_indices.add(j)

                    visited.add(j)

                    queue.append(j)

        # -------------------------------------------------
        # BUILD RAW CLUSTER
        # -------------------------------------------------

        cluster = [
            events[index]
            for index in sorted(
                cluster_indices
            )
        ]

        incidents.append(cluster)

    # -----------------------------------------------------
    # BUILD INCIDENT OBJECTS
    # -----------------------------------------------------

    incident_objects = []

    for cluster in incidents:

        incident = build_incident(
            cluster
        )

        if incident:

            incident_objects.append(
                incident
            )

    return incident_objects