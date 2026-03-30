from wazuh_api import manager_request


def fetch_agents():
    data = manager_request("/agents")
    return data["data"]["affected_items"]