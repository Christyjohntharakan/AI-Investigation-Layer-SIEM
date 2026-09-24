def explain_event_features(event):
    """
    Explain the main security features that
    contributed to the event risk.

    This is a lightweight SHAP-style explanation
    based on the existing risk/classification fields.
    """

    features = []

    risk_score = event.get("risk_score", 0)
    severity = event.get("severity")
    category = event.get("category")
    event_type = event.get("event_type")
    mitre_techniques = event.get(
        "mitre_techniques",
        []
    )

    # Risk score contribution
    if risk_score >= 80:
        features.append({
            "feature": "Risk Score",
            "value": risk_score,
            "contribution": 0.45
        })

    elif risk_score >= 50:
        features.append({
            "feature": "Risk Score",
            "value": risk_score,
            "contribution": 0.30
        })

    else:
        features.append({
            "feature": "Risk Score",
            "value": risk_score,
            "contribution": 0.15
        })

    # Severity contribution
    if severity:
        features.append({
            "feature": "Severity",
            "value": severity,
            "contribution": 0.25
        })

    # Category contribution
    if category:
        features.append({
            "feature": "Event Category",
            "value": category,
            "contribution": 0.15
        })

    # Event type contribution
    if event_type:
        features.append({
            "feature": "Event Type",
            "value": event_type,
            "contribution": 0.10
        })

    # MITRE contribution
    if mitre_techniques:
        features.append({
            "feature": "MITRE Technique",
            "value": mitre_techniques,
            "contribution": 0.20
        })

    return features