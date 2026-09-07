import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


OPENSEARCH_URL = "https://localhost:9200"
USERNAME = "admin"
PASSWORD = "SecretPassword"


def fetch_logs(size=20):
    """
    Fetch the latest Wazuh alerts from OpenSearch
    and normalize them into a common security-event format.
    """

    url = (
        f"{OPENSEARCH_URL}/wazuh-alerts-4.x-*/_search"
        f"?size={size}&sort=@timestamp:desc"
    )

    response = requests.get(
        url,
        auth=(USERNAME, PASSWORD),
        verify=False,
    )

    response.raise_for_status()

    data = response.json()

    normalized_logs = []

    for hit in data["hits"]["hits"]:

        src = hit["_source"]

        # -------------------------------------------------
        # RULE INFORMATION
        # -------------------------------------------------

        rule_data = src.get("rule", {})

        rule_id = rule_data.get("id")
        rule_description = rule_data.get("description")
        severity = rule_data.get("level")
        rule_groups = rule_data.get("groups", [])


        # -------------------------------------------------
        # MITRE ATT&CK INFORMATION
        # -------------------------------------------------
        # Normal Wazuh security rules may contain:
        #
        # rule.mitre.id
        # rule.mitre.tactic
        #
        # Some events such as SCA use:
        #
        # rule.mitre_techniques
        # rule.mitre_tactics
        #
        # We support both formats.
        # -------------------------------------------------

        mitre_data = rule_data.get("mitre", {})

        mitre_techniques = mitre_data.get("id", [])
        mitre_tactics = mitre_data.get("tactic", [])

        if not mitre_techniques:
            mitre_techniques = rule_data.get(
                "mitre_techniques",
                []
            )

        if not mitre_tactics:
            mitre_tactics = rule_data.get(
                "mitre_tactics",
                []
            )


        # -------------------------------------------------
        # AGENT INFORMATION
        # -------------------------------------------------

        agent_data = src.get("agent", {})

        agent_name = agent_data.get("name")
        agent_id = agent_data.get("id")
        agent_ip = agent_data.get("ip")


        # -------------------------------------------------
        # EVENT DATA
        # -------------------------------------------------

        event_data = src.get("data", {})

        source_user = event_data.get("srcuser")
        destination_user = event_data.get("dstuser")

        source_ip = event_data.get("srcip")
        destination_ip = event_data.get("dstip")


        # -------------------------------------------------
        # DECODER / LOG INFORMATION
        # -------------------------------------------------

        decoder_data = src.get("decoder", {})

        decoder = decoder_data.get("name")

        event_type = src.get(
            "input",
            {}
        ).get("type")

        location = src.get("location")

        message = src.get("full_log")


        # -------------------------------------------------
        # CREATE NORMALIZED SECURITY EVENT
        # -------------------------------------------------

        normalized_event = {

            "timestamp": src.get("@timestamp"),

            # Agent
            "agent_name": agent_name,
            "agent_id": agent_id,
            "agent_ip": agent_ip,

            # Wazuh rule
            "rule_id": rule_id,
            "rule_description": rule_description,
            "severity": severity,
            "rule_groups": rule_groups,

            # Event details
            "event_type": event_type,
            "decoder": decoder,
            "location": location,
            "message": message,

            # Users
            "source_user": source_user,
            "destination_user": destination_user,

            # Network
            "source_ip": source_ip,
            "destination_ip": destination_ip,

            # MITRE ATT&CK
            "mitre_techniques": mitre_techniques,
            "mitre_tactics": mitre_tactics,
        }

        normalized_logs.append(normalized_event)


    return normalized_logs