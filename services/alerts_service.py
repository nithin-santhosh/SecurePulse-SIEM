from wazuh_api import indexer_search
from datetime import datetime, timedelta, timezone

def format_timestamp(ts):
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")

        # convert UTC → IST
        ist = timezone(timedelta(hours=5, minutes=30))
        dt = dt.astimezone(ist)

        return dt.strftime("%d %b %Y %H:%M:%S")
    except Exception:
        return ts


def fetch_alerts(limit=50):
    query = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"match_all": {}}
    }

    data = indexer_search(query)
    hits = data["hits"]["hits"]

    alerts = []

    for hit in hits:
        src = hit["_source"]

        alert = {
            "timestamp": format_timestamp(src.get("@timestamp", "N/A")),
            "agent": src.get("agent", {}).get("name", "unknown"),
            "rule": src.get("rule", {}).get("description", "No description"),
            "level": src.get("rule", {}).get("level", 0)
        }

        alerts.append(alert)

    return alerts