def calculate_risk_score(
    ml_confidence=0,
    mitre_severity=0,
    asset_criticality=0,
    memory_match=0
):
    """
    Calculate the overall security risk score.

    All input values should be between 0 and 100.

    Weighting:
    - ML confidence: 25%
    - MITRE severity: 30%
    - Asset criticality: 25%
    - Memory match: 20%
    """

    risk_score = (
        (ml_confidence * 0.25)
        + (mitre_severity * 0.30)
        + (asset_criticality * 0.25)
        + (memory_match * 0.20)
    )

    # Keep the score between 0 and 100
    risk_score = max(
        0,
        min(100, risk_score)
    )

    return round(
        risk_score,
        2
    )


def get_risk_level(risk_score):
    """
    Convert the numerical risk score
    into a risk level.
    """

    if risk_score >= 80:
        return "Critical"

    if risk_score >= 60:
        return "High"

    if risk_score >= 40:
        return "Medium"

    return "Low"