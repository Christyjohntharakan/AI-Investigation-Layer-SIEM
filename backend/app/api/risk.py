from fastapi import APIRouter

from app.services.risk_intelligence.risk_engine import (
    calculate_incident_risk,
)


router = APIRouter()


@router.get("/risk")
def get_risk():

    # Sample incident data for the API structure.
    # Real Wazuh incident data will be connected later.
    incident = {
        "incident_id": "sample-incident"
    }

    risk_result = calculate_incident_risk(
        incident=incident,
        ml_confidence=0,
        mitre_severity=0,
        asset_criticality=0,
        memory_match=0,
    )

    return risk_result