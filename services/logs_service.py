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


def fetch_logs(keyword=None, severity=None, agent=None, limit=50):
    must_clauses = []

    if keyword:
        must_clauses.append({
            "multi_match": {
                "query": keyword,
                "fields": ["rule.description", "agent.name", "full_log"]
            }
        })

    if severity:
        must_clauses.append({
            "term": {
                "rule.level": int(severity)
            }
        })

    if agent:
        must_clauses.append({
            "match": {
                "agent.name": agent
            }
        })

    query = {
        "size": limit,
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ],
        "query": {
            "bool": {
                "must": must_clauses if must_clauses else [{"match_all": {}}]
            }
        }
    }

    data = indexer_search(query)
    hits = data["hits"]["hits"]

    logs = []

    for hit in hits:
        src = hit["_source"]

        # convert timestamp safely
        if "@timestamp" in src:
            src["@timestamp"] = format_timestamp(src["@timestamp"])

        logs.append(src)

    return logs