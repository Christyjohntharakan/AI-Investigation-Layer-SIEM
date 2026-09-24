from fastapi import APIRouter

from app.services.decision.decision_engine import make_decision


router = APIRouter()


@router.get("/decision")
def get_decision():

    # Sample incident data for the API structure.
    # Real incident data will be connected through
    # the investigation pipeline later.
    incident = {
        "incident_id": "sample-incident"
    }

    decision = make_decision(
        incident=incident,
        risk_score=76.5,
        risk_level="High",
        mitre_techniques=[],
        memory_match=0,
    )

    return decision