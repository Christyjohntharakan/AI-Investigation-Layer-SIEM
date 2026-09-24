# MITRE ATT&CK verification rules

MITRE_RULES = {

    # Command and Scripting Interpreter
    "powershell": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution"
    },

    "command shell": {
        "technique_id": "T1059.003",
        "technique_name": "Windows Command Shell",
        "tactic": "Execution"
    },

    # Credential Access
    "credential dumping": {
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "Credential Access"
    },

    "password dumping": {
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "Credential Access"
    },

    # Privilege Escalation
    "privilege escalation": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation"
    },

    # Persistence
    "scheduled task": {
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "tactic": "Persistence"
    },

    # Discovery
    "system information discovery": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "Discovery"
    },

    "account discovery": {
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "tactic": "Discovery"
    },

    "process discovery": {
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
        "tactic": "Discovery"
    },

    # Defense Evasion
    "file deletion": {
        "technique_id": "T1070.004",
        "technique_name": "File Deletion",
        "tactic": "Defense Evasion"
    },

    # Lateral Movement
    "remote services": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement"
    }
}


def verify_mitre_rule(event):
    """
    Verify whether an event matches one of the
    known MITRE ATT&CK behavior rules.
    """

    matched_rules = []

    # Collect searchable event information
    values = [
        event.get("event_type"),
        event.get("rule_description"),
        event.get("message")
    ]

    searchable_text = " ".join(
        str(value).lower()
        for value in values
        if value
    )

    # Check each MITRE rule
    for keyword, rule in MITRE_RULES.items():

        if keyword in searchable_text:

            matched_rules.append({
                "keyword": keyword,
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "tactic": rule["tactic"]
            })

    return matched_rules