from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel


class SecurityEvent(BaseModel):
    timestamp: Optional[datetime] = None

    # Event source
    agent_name: Optional[str] = None
    agent_id: Optional[str] = None
    agent_ip: Optional[str] = None

    # Wazuh rule
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    severity: Optional[int] = None
    rule_groups: List[str] = []

    # Event details
    event_type: Optional[str] = None
    decoder: Optional[str] = None
    location: Optional[str] = None
    message: Optional[str] = None

    # Users
    source_user: Optional[str] = None
    destination_user: Optional[str] = None

    # Network
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None

    # MITRE ATT&CK
    mitre_techniques: List[str] = []
    mitre_tactics: List[str] = []

    # Classification
    category: Optional[str] = None
    priority: Optional[str] = None