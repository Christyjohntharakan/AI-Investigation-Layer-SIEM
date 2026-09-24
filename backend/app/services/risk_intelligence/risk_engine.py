from app.services.risk_intelligence.risk_calculator import (
    calculate_risk_score,
    get_risk_level,
)


def calculate_incident_risk(
    incident,
    ml_confidence=0,
    mitre_severity=0,
    asset_criticality=0,
    memory_match=0,
):
    """
    Calculate the overall risk of a security incident.

    The incident is combined with four risk factors:
    - ML confidence
    - MITRE severity
    - Asset criticality
    - Memory match
    """

    risk_score = calculate_risk_score(
        ml_confidence=ml_confidence,
        mitre_severity=mitre_severity,
        asset_criticality=asset_criticality,
        memory_match=memory_match,
    )

    risk_level = get_risk_level(risk_score)

    return {
        "incident_id": incident.get("incident_id"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "factors": {
            "ml_confidence": ml_confidence,
            "mitre_severity": mitre_severity,
            "asset_criticality": asset_criticality,
            "memory_match": memory_match,
        },
    }