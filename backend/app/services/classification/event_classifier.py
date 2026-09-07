def classify_event(event):
    """
    Classify a normalized Wazuh event and calculate
    an explainable risk score and priority.
    """

    rule = (event.get("rule_description") or "").lower()

    groups = [
        group.lower()
        for group in event.get("rule_groups", [])
    ]

    severity = event.get("severity") or 0

    try:
        severity = int(severity)
    except (ValueError, TypeError):
        severity = 0

    mitre_techniques = event.get("mitre_techniques", [])
    mitre_tactics = event.get("mitre_tactics", [])

    # ==================================================
    # 1. EVENT CATEGORY
    # ==================================================

    if "sca" in groups:
        category = "compliance"

    elif any(
        keyword in rule
        for keyword in [
            "failed login",
            "authentication failure",
            "authentication failed",
            "invalid user",
            "brute force",
        ]
    ):
        category = "authentication"

    elif (
        "authentication_success" in groups
        or "authentication" in groups
        or "pam" in groups
    ):
        category = "authentication"

    elif any(
        keyword in rule
        for keyword in [
            "sudo",
            "privilege",
            "root",
            "escalation",
        ]
    ):
        category = "privilege"

    elif any(
        keyword in rule
        for keyword in [
            "integrity",
            "checksum changed",
            "file modified",
            "syscheck",
        ]
    ):
        category = "file_integrity"

    elif any(
        keyword in rule
        for keyword in [
            "malware",
            "trojan",
            "virus",
            "ransomware",
        ]
    ):
        category = "malware"

    elif any(
        keyword in rule
        for keyword in [
            "network",
            "connection",
            "firewall",
            "port",
        ]
    ):
        category = "network"

    elif "ossec" in groups:
        category = "system"

    else:
        category = "other"

    # ==================================================
    # 2. RISK SCORING
    # ==================================================

    risk_score = 0
    factors = []

    # --------------------------------------------------
    # Factor 1: Wazuh Severity
    # --------------------------------------------------

    severity_contribution = severity * 5

    risk_score += severity_contribution

    factors.append({
        "factor": "Wazuh severity",
        "value": severity,
        "contribution": severity_contribution,
        "reason": (
            f"Wazuh assigned severity level {severity}. "
            f"The severity contributes {severity_contribution} "
            "points to the risk score."
        )
    })

    # --------------------------------------------------
    # Factor 2: Event Category
    # --------------------------------------------------

    category_weights = {
        "malware": 30,
        "privilege": 20,
        "network": 10,
        "authentication": 5,
        "file_integrity": 15,
        "compliance": 5,
        "system": 0,
        "other": 0
    }

    category_contribution = category_weights.get(
        category,
        0
    )

    risk_score += category_contribution

    if category_contribution > 0:

        factors.append({
            "factor": "Event category",
            "value": category,
            "contribution": category_contribution,
            "reason": (
                f"The event was classified as "
                f"{category}. This category contributes "
                f"{category_contribution} points."
            )
        })

    # --------------------------------------------------
    # Factor 3: MITRE ATT&CK
    # --------------------------------------------------

    if mitre_techniques:

        mitre_contribution = 10

        risk_score += mitre_contribution

        factors.append({
            "factor": "MITRE ATT&CK mapping",
            "value": mitre_techniques,
            "contribution": mitre_contribution,
            "reason": (
                "The event is mapped to one or more "
                "MITRE ATT&CK techniques, indicating "
                "security-relevant attacker behavior."
            )
        })

    # --------------------------------------------------
    # Factor 4: Privileged Account Activity
    # --------------------------------------------------

    destination_user = (
        event.get("destination_user") or ""
    ).lower()

    if destination_user == "root":

        root_contribution = 10

        risk_score += root_contribution

        factors.append({
            "factor": "Root account activity",
            "value": destination_user,
            "contribution": root_contribution,
            "reason": (
                "The event involves access to the "
                "root account, increasing the potential "
                "impact of the activity."
            )
        })

    # --------------------------------------------------
    # Cap Score
    # --------------------------------------------------

    risk_score = min(risk_score, 100)

    # ==================================================
    # 3. PRIORITY
    # ==================================================

    if risk_score >= 80:
        priority = "critical"

    elif risk_score >= 60:
        priority = "high"

    elif risk_score >= 30:
        priority = "medium"

    else:
        priority = "low"

    # ==================================================
    # 4. EXPLANATION SUMMARY
    # ==================================================

    if priority == "critical":
        summary = (
            "Critical-risk event requiring immediate "
            "analyst attention."
        )

    elif priority == "high":
        summary = (
            "High-risk security event requiring "
            "prompt investigation."
        )

    elif priority == "medium":
        summary = (
            "Medium-risk security event with "
            "security-relevant indicators."
        )

    else:
        summary = (
            "Low-risk event with limited immediate "
            "security impact."
        )

    # ==================================================
    # 5. ADD RESULTS TO EVENT
    # ==================================================

    event["category"] = category
    event["risk_score"] = risk_score
    event["priority"] = priority

    event["risk_explanation"] = {
        "summary": summary,
        "factors": factors
    }

    return event