from collections import Counter


# ============================================================
# INCIDENT RISK CONFIGURATION
# ============================================================

MAX_RISK = 100


# Additional risk caused by incident-level context
EVENT_COUNT_BONUS = {
    1: 0,
    2: 10,
    3: 15,
    4: 20,
}

MITRE_TECHNIQUE_BONUS = 10
MITRE_TACTIC_BONUS = 5
ROOT_ACTIVITY_BONUS = 10
REPEATED_RULE_BONUS = 10


# ============================================================
# HELPER
# ============================================================

def clamp(value, minimum=0, maximum=MAX_RISK):
    return max(minimum, min(value, maximum))


# ============================================================
# PRIORITY
# ============================================================

def risk_priority(score):
    """
    Convert the project's 0-100 risk score into a priority.
    """

    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 40:
        return "medium"

    return "low"


# ============================================================
# INCIDENT RISK
# ============================================================

def calculate_incident_risk(events):
    """
    Calculate an explainable incident-level risk score.

    Returns:
        {
            "risk_score": int,
            "priority": str,
            "risk_explanation": {...}
        }
    """

    if not events:
        return {
            "risk_score": 0,
            "priority": "low",
            "risk_explanation": {
                "summary": "No events were available for risk analysis.",
                "factors": []
            }
        }


    factors = []


    # ========================================================
    # 1. BASE EVENT RISK
    # ========================================================

    event_risks = [
        event.get("risk_score", 0)
        for event in events
    ]

    max_event_risk = max(event_risks)

    score = max_event_risk

    factors.append({
        "factor": "Highest event risk",
        "value": max_event_risk,
        "contribution": max_event_risk,
        "reason": (
            f"The highest individual event risk in the incident "
            f"is {max_event_risk}."
        )
    })


    # ========================================================
    # 2. EVENT COUNT / REPEATED ACTIVITY
    # ========================================================

    event_count = len(events)

    event_count_bonus = EVENT_COUNT_BONUS.get(
        min(event_count, 4),
        20
    )

    if event_count_bonus > 0:

        score += event_count_bonus

        factors.append({
            "factor": "Related event count",
            "value": event_count,
            "contribution": event_count_bonus,
            "reason": (
                f"The incident contains {event_count} related "
                f"events, indicating repeated or coordinated activity."
            )
        })


    # ========================================================
    # 3. MITRE TECHNIQUES
    # ========================================================

    techniques = set()

    for event in events:

        techniques.update(
            event.get("mitre_techniques", [])
        )

    if techniques:

        technique_bonus = min(
            len(techniques) * MITRE_TECHNIQUE_BONUS,
            20
        )

        score += technique_bonus

        factors.append({
            "factor": "MITRE ATT&CK techniques",
            "value": sorted(techniques),
            "contribution": technique_bonus,
            "reason": (
                f"The incident contains {len(techniques)} "
                f"MITRE ATT&CK technique(s), indicating "
                f"security-relevant behavior."
            )
        })


    # ========================================================
    # 4. MITRE TACTICS
    # ========================================================

    tactics = set()

    for event in events:

        tactics.update(
            event.get("mitre_tactics", [])
        )

    if len(tactics) >= 2:

        score += MITRE_TACTIC_BONUS

        factors.append({
            "factor": "MITRE tactic diversity",
            "value": sorted(tactics),
            "contribution": MITRE_TACTIC_BONUS,
            "reason": (
                f"The incident spans {len(tactics)} MITRE "
                f"ATT&CK tactics, suggesting activity across "
                f"multiple stages of an attack."
            )
        })


    # ========================================================
    # 5. ROOT ACCOUNT ACTIVITY
    # ========================================================

    root_activity = False

    for event in events:

        source_user = event.get("source_user")
        destination_user = event.get("destination_user")

        if (
            source_user == "root"
            or destination_user == "root"
        ):
            root_activity = True
            break


    if root_activity:

        score += ROOT_ACTIVITY_BONUS

        factors.append({
            "factor": "Root account activity",
            "value": "root",
            "contribution": ROOT_ACTIVITY_BONUS,
            "reason": (
                "The incident involves the root account, "
                "increasing its potential impact."
            )
        })


    # ========================================================
    # 6. REPEATED RULE
    # ========================================================

    rule_ids = [
        event.get("rule_id")
        for event in events
        if event.get("rule_id") is not None
    ]

    rule_counts = Counter(rule_ids)

    repeated_rules = {
        rule: count
        for rule, count in rule_counts.items()
        if count > 1
    }

    if repeated_rules:

        score += REPEATED_RULE_BONUS

        factors.append({
            "factor": "Repeated detection rule",
            "value": repeated_rules,
            "contribution": REPEATED_RULE_BONUS,
            "reason": (
                "The same Wazuh detection rule occurred "
                "multiple times within the incident."
            )
        })


    # ========================================================
    # FINAL SCORE
    # ========================================================

    score = clamp(score)

    priority = risk_priority(score)


    # ========================================================
    # SUMMARY
    # ========================================================

    summaries = {
        "critical": (
            "Critical-risk incident requiring immediate investigation "
            "and response."
        ),

        "high": (
            "High-risk incident requiring prompt investigation."
        ),

        "medium": (
            "Medium-risk incident containing security-relevant "
            "indicators."
        ),

        "low": (
            "Low-risk incident with limited immediate security impact."
        )
    }


    return {
        "risk_score": score,
        "priority": priority,

        "risk_explanation": {
            "summary": summaries[priority],
            "factors": factors
        }
    }