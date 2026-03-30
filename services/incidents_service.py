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


def fetch_incidents(limit=50):
    """
    Fetch critical incidents (rule.level >= 10)
    """

    query = {
        "size": limit,
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ],
        "query": {
            "range": {
                "rule.level": {
                    "gte": 10
                }
            }
        }
    }

    data = indexer_search(query)
    hits = data["hits"]["hits"]

    incidents = []

    for hit in hits:
        src = hit["_source"]

        # convert timestamp
        if "@timestamp" in src:
            src["@timestamp"] = format_timestamp(src["@timestamp"])

        incidents.append(src)

    return incidents