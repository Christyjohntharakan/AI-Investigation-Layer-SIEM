import os

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams


QDRANT_URL = os.getenv(
    "QDRANT_URL",
    "http://localhost:6333"
)

COLLECTION_NAME = os.getenv(
    "QDRANT_COLLECTION",
    "security_incidents"
)

VECTOR_SIZE = 768


_client = None


def get_qdrant_client():
    """
    Create and return the Qdrant client.
    """

    global _client

    if _client is None:

        _client = QdrantClient(
            url=QDRANT_URL
        )

    return _client


def ensure_collection():
    """
    Create the incident collection if it does not exist.
    """

    client = get_qdrant_client()

    collections = client.get_collections()

    existing_collections = [
        collection.name
        for collection in collections.collections
    ]

    if COLLECTION_NAME not in existing_collections:

        client.create_collection(
            collection_name=COLLECTION_NAME,

            vectors_config=VectorParams(
                size=VECTOR_SIZE,
                distance=Distance.COSINE
            )
        )

    return COLLECTION_NAME