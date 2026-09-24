def generate_recommendations(
    incident,
    risk_score=0,
    risk_level="Low",
    mitre_techniques=None,
    source_ip=None,
    source_user=None,
):
    """
    Generate security recommendations for an analyst.

    This module only suggests actions.
    It does not automatically execute any security action.
    """

    if mitre_techniques is None:
        mitre_techniques = []

    recommendations = []

    # Basic recommendation based on risk level.
    if risk_score >= 80:
        recommendations.append({
            "action": "Isolate Endpoint",
            "reason": "The incident has a critical risk score.",
            "priority": "Critical",
        })

        recommendations.append({
            "action": "Notify SOC",
            "reason": "Immediate analyst attention is required.",
            "priority": "Critical",
        })

    elif risk_score >= 60:
        recommendations.append({
            "action": "Investigate Incident",
            "reason": "The incident has a high risk score.",
            "priority": "High",
        })

        recommendations.append({
            "action": "Notify SOC",
            "reason": "The incident should be reviewed by the security team.",
            "priority": "High",
        })

    elif risk_score >= 40:
        recommendations.append({
            "action": "Investigate Incident",
            "reason": "The incident has a medium risk score.",
            "priority": "Medium",
        })

    else:
        recommendations.append({
            "action": "Continue Monitoring",
            "reason": "The current risk score is low.",
            "priority": "Low",
        })

    # If a source IP is available, recommend reviewing it.
    if source_ip:
        recommendations.append({
            "action": "Review Source IP",
            "reason": f"Investigate activity associated with {source_ip}.",
            "priority": "High",
        })

    # If a source user is available, recommend checking the account.
    if source_user:
        recommendations.append({
            "action": "Review User Account",
            "reason": f"Check the activity of user {source_user}.",
            "priority": "High",
        })

    # MITRE techniques provide additional investigation context.
    if mitre_techniques:
        recommendations.append({
            "action": "Review MITRE ATT&CK Techniques",
            "reason": "Investigate the techniques associated with this incident.",
            "priority": "Medium",
        })

    return {
        "incident_id": incident.get("incident_id"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "recommendations": recommendations,
    }