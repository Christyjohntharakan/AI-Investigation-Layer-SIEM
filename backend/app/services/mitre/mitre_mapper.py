from app.services.mitre.mitre_rules import verify_mitre_rule


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

    The mapper uses:
    1. MITRE information already provided by Wazuh
    2. Rule verification based on event behavior

    The two sources are compared to produce a verified mapping.
    """

    # ---------------------------------------------------------
    # 1. Get MITRE information already available from Wazuh
    # ---------------------------------------------------------

    wazuh_techniques = _clean_list(
        event.get("mitre_techniques")
    )

    wazuh_tactics = _clean_list(
        event.get("mitre_tactics")
    )

    # ---------------------------------------------------------
    # 2. Verify the event using our MITRE rules
    # ---------------------------------------------------------

    verified_rules = verify_mitre_rule(event)

    # Extract verified technique IDs
    verified_techniques = [
        rule["technique_id"]
        for rule in verified_rules
    ]

    # Extract verified technique names
    verified_names = [
        rule["technique_name"]
        for rule in verified_rules
    ]

    # Extract verified tactics
    verified_tactics = [
        rule["tactic"]
        for rule in verified_rules
    ]

    # ---------------------------------------------------------
    # 3. Combine Wazuh + rule verification
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
    # 4. Determine verification status
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
    # 5. Build final MITRE mapping
    # ---------------------------------------------------------

    mapping = []

    # Add mappings from verified rules
    for rule in verified_rules:

        mapping.append({
            "technique_id": rule["technique_id"],
            "technique_name": rule["technique_name"],
            "tactic": rule["tactic"],
            "source": "rule_verification"
        })

    # Add Wazuh mappings
    for technique in wazuh_techniques:

        # Avoid duplicate technique IDs
        already_exists = any(
            item["technique_id"] == technique
            for item in mapping
        )

        if not already_exists:

            mapping.append({
                "technique_id": technique,
                "technique_name": None,
                "tactic": None,
                "source": "wazuh"
            })

    # ---------------------------------------------------------
    # 6. Return complete MITRE result
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