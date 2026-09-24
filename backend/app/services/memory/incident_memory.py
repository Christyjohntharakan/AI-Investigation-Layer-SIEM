from qdrant_client.models import PointStruct

from app.services.memory.qdrant_client import (
    get_qdrant_client,
    ensure_collection,
    COLLECTION_NAME,
)


def store_incident(
    incident_id,
    embedding,
    incident
):
    """
    Store an incident in Qdrant.
    """

    client = get_qdrant_client()

    ensure_collection()

    point = PointStruct(
        id=incident_id,
        vector=embedding,
        payload=incident
    )

    client.upsert(
        collection_name=COLLECTION_NAME,
        points=[point]
    )

    return {
        "incident_id": incident_id,
        "stored": True
    }


def find_similar_incidents(
    embedding,
    limit=5
):
    """
    Find previous incidents that are
    similar to the current incident.
    """

    client = get_qdrant_client()

    ensure_collection()

    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=embedding,
        limit=limit,
        with_payload=True
    )

    similar_incidents = []

    for result in results.points:

        similar_incidents.append({
            "incident_id":
                result.payload.get(
                    "incident_id"
                ),

            "similarity_score":
                result.score,

            "incident":
                result.payload
        })

    return similar_incidents