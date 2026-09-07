import requests

WAZUH_URL = "https://localhost:55000"
USERNAME = "wazuh-wui"
PASSWORD = "MyS3cr37P450r.*-"


def get_token():
    response = requests.get(
        f"{WAZUH_URL}/security/user/authenticate?raw=true",
        auth=(USERNAME, PASSWORD),
        verify=False
    )

    response.raise_for_status()
    return response.text


def get_latest_alerts(limit=5):
    token = get_token()

    headers = {
        "Authorization": f"Bearer {token}"
    }

    response = requests.get(
        f"{WAZUH_URL}/alerts",
        headers=headers,
        params={"limit": limit},
        verify=False
    )

    response.raise_for_status()

    return response.json()