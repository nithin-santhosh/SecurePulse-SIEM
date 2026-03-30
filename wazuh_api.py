import requests
import urllib3
import os
from dotenv import load_dotenv

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------
# CONFIGURATION (CHANGE IP HERE ONLY)
# ---------------------------------

# Load from .env
HOST_IP = os.getenv("HOST_IP")

MANAGER_PORT = os.getenv("MANAGER_PORT")
INDEXER_PORT = os.getenv("INDEXER_PORT")

MANAGER_USER = os.getenv("MANAGER_USER")
MANAGER_PASS = os.getenv("MANAGER_PASS")

INDEXER_USER = os.getenv("INDEXER_USER")
INDEXER_PASS = os.getenv("INDEXER_PASS")

# Construct URLs dynamically
WAZUH_MANAGER_URL = f"https://{HOST_IP}:{MANAGER_PORT}"
INDEXER_URL = f"https://{HOST_IP}:{INDEXER_PORT}"


# -------------------------
# MANAGER REQUEST
# -------------------------

def manager_request(endpoint):
    auth_response = requests.post(
        f"{WAZUH_MANAGER_URL}/security/user/authenticate",
        auth=(MANAGER_USER, MANAGER_PASS),
        verify=False
    )

    if auth_response.status_code != 200:
        raise Exception("Manager authentication failed")

    token = auth_response.json()["data"]["token"]

    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(
        f"{WAZUH_MANAGER_URL}{endpoint}",
        headers=headers,
        verify=False
    )

    if response.status_code != 200:
        raise Exception(response.text)

    return response.json()


# -------------------------
# INDEXER SEARCH
# -------------------------

def indexer_search(query):
    response = requests.post(
        f"{INDEXER_URL}/wazuh-alerts-*/_search",
        auth=(INDEXER_USER, INDEXER_PASS),
        json=query,
        verify=False
    )

    if response.status_code != 200:
        raise Exception(response.text)

    return response.json()