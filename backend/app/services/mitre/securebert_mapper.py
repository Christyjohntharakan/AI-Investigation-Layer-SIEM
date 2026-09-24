from app.services.mitre.mitre_rules import verify_mitre_rule
from app.services.mitre.securebert_mapper import (
    encode_security_event
)


def _clean_list(value):
    """
    Make sure MITRE techniques/tactics are returned as lists.
    """

    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def map_mitre_event(event):
    """
    Map a security event to MITRE ATT&CK.

    Sources used:
    1. Wazuh MITRE information
    2. SecureBERT representation
    3. MITRE rule verification
    """

    # ---------------------------------------------------------
    # 1. Get MITRE information from Wazuh
    # ---------------------------------------------------------

    wazuh_techniques = _clean_list(
        event.get("mitre_techniques")
    )

    wazuh_tactics = _clean_list(
        event.get("mitre_tactics")
    )

    # ---------------------------------------------------------
    # 2. Generate SecureBERT representation
    # ---------------------------------------------------------

    securebert_result = encode_security_event(
        event
    )

    # ---------------------------------------------------------
    # 3. Verify using MITRE rules
    # ---------------------------------------------------------

    verified_rules = verify_mitre_rule(
        event
    )

    verified_techniques = [
        rule["technique_id"]
        for rule in verified_rules
    ]

    verified_names = [
        rule["technique_name"]
        for rule in verified_rules
    ]

    verified_tactics = [
        rule["tactic"]
        for rule in verified_rules
    ]

    # ---------------------------------------------------------
    # 4. Combine Wazuh + verified MITRE information
    # ---------------------------------------------------------

    techniques = []

    for technique in wazuh_techniques:

        if technique not in techniques:
            techniques.append(technique)

    for technique in verified_techniques:

        if technique not in techniques:
            techniques.append(technique)

    tactics = []

    for tactic in wazuh_tactics:

        if tactic not in tactics:
            tactics.append(tactic)

    for tactic in verified_tactics:

        if tactic not in tactics:
            tactics.append(tactic)

    # ---------------------------------------------------------
    # 5. Determine verification status
    # ---------------------------------------------------------

    if wazuh_techniques and verified_techniques:

        verification_status = "verified"

    elif wazuh_techniques:

        verification_status = "wazuh_mapped"

    elif verified_techniques:

        verification_status = "rule_verified"

    else:

        verification_status = "unmapped"

    # ---------------------------------------------------------
    # 6. Build final MITRE mapping
    # ---------------------------------------------------------

    mapping = []

    for rule in verified_rules:

        mapping.append({
            "technique_id":
                rule["technique_id"],

            "technique_name":
                rule["technique_name"],

            "tactic":
                rule["tactic"],

            "source":
                "rule_verification"
        })

    for technique in wazuh_techniques:

        already_exists = any(
            item["technique_id"] == technique
            for item in mapping
        )

        if not already_exists:

            mapping.append({
                "technique_id":
                    technique,

                "technique_name":
                    None,

                "tactic":
                    None,

                "source":
                    "wazuh"
            })

    # ---------------------------------------------------------
    # 7. Return complete MITRE result
    # ---------------------------------------------------------

    return {

        "event_type":
            event.get("event_type"),

        "category":
            event.get("category"),

        "description":
            event.get("rule_description")
            or event.get("message")
            or event.get("event_type"),

        "mitre_techniques":
            techniques,

        "mitre_tactics":
            tactics,

        "verified_technique_names":
            verified_names,

        "verification_status":
            verification_status,

        "securebert": {
            "model":
                "ehsanaghaei/SecureBERT",

            "text":
                securebert_result["text"],

            "embedding_dimension":
                len(
                    securebert_result["embedding"]
                )
        },

        "mapping":
            mapping
    }


def map_mitre_events(events):
    """
    Map multiple security events to MITRE ATT&CK.
    """

    results = []

    for event in events:

        results.append(
            map_mitre_event(event)
        )

    return results