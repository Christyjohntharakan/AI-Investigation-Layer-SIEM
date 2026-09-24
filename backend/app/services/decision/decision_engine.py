def make_decision(
    incident,
    risk_score=0,
    risk_level="Low",
    mitre_techniques=None,
    memory_match=0,
):
    """
    Generate structured decision support for a security incident.

    This module does not automatically take action.
    It only provides recommendations for the security analyst.
    """

    if mitre_techniques is None:
        mitre_techniques = []

    decisions = []

    # High-risk incidents need immediate analyst attention.
    if risk_score >= 80:
        decisions.append("Immediate investigation required")

    elif risk_score >= 60:
        decisions.append("Prioritize for investigation")

    elif risk_score >= 40:
        decisions.append("Monitor and investigate")

    else:
        decisions.append("Continue monitoring")

    # MITRE ATT&CK information can provide additional context.
    if mitre_techniques:
        decisions.append(
            "Review the mapped MITRE ATT&CK techniques"
        )

    # Historical memory matches can help the analyst
    # compare the current incident with previous incidents.
    if memory_match >= 60:
        decisions.append(
            "Compare with similar historical incidents"
        )

    return {
        "incident_id": incident.get("incident_id"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "mitre_techniques": mitre_techniques,
        "memory_match": memory_match,
        "decision_support": decisions,
    }