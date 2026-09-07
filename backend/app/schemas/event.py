from pydantic import BaseModel

class Event(BaseModel):
    timestamp: str
    hostname: str
    source_ip: str
    destination_ip: str
    event_type: str
    severity: str