from fastapi import APIRouter

from app.services.recommendation.recommendation_engine import (
    generate_recommendations,
)


router = APIRouter()


@router.get("/recommendations")
def get_recommendations():

    # Sample incident data for the API structure.
    # Real incident data will be connected through
    # the investigation pipeline later.
    incident = {
        "incident_id": "sample-incident"
    }

    recommendations = generate_recommendations(
        incident=incident,
        risk_score=76.5,
        risk_level="High",
        mitre_techniques=[],
        source_ip=None,
        source_user=None,
    )

    return recommendations