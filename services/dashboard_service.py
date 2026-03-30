from wazuh_api import indexer_search, manager_request
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

def fetch_dashboard_metrics():

    # -------------------------
    # ALERT SEVERITY AGGREGATION
    # -------------------------

    query = {
        "size": 0,
        "aggs": {
            "severity_distribution": {
                "terms": {
                    "field": "rule.level",
                    "size": 15
                }
            }
        }
    }

    alert_data = indexer_search(query)
    buckets = alert_data.get("aggregations", {}).get("severity_distribution", {}).get("buckets", [])

    low = 0
    medium = 0
    high = 0
    critical = 0

    for bucket in buckets:

        level = bucket["key"]
        count = bucket["doc_count"]

        if level <= 3:
            low += count
        elif 4 <= level <= 6:
            medium += count
        elif 7 <= level <= 9:
            high += count
        else:
            critical += count

    total_alerts = low + medium + high + critical

    # -------------------------
    # AGENT STATUS
    # -------------------------

    agents_data = manager_request("/agents")
    agents_list = agents_data.get("data", {}).get("affected_items", [])

    active_agents = len([a for a in agents_list if a.get("status") == "active"])
    offline_agents = len([a for a in agents_list if a.get("status") != "active"])

    # -------------------------
    # RECENT CRITICAL ALERTS
    # -------------------------

    recent_query = {
        "size": 5,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "range": {
                "rule.level": {
                    "gte": 7
                }
            }
        }
    }

    recent_data = indexer_search(recent_query)

    recent_alerts = []

    for hit in recent_data.get("hits", {}).get("hits", []):

        src = hit.get("_source", {})

        recent_alerts.append({
            "time": format_timestamp(src.get("@timestamp")),
            "agent": src.get("agent", {}).get("name", "unknown"),
            "rule": src.get("rule", {}).get("description", "unknown")
        })

    # -------------------------
    # TOP ATTACKING IPS
    # -------------------------

    ip_query = {
        "size": 0,
        "aggs": {
            "top_attackers": {
                "terms": {
                    "field": "data.srcip",
                    "size": 5
                }
            }
        }
    }

    ip_data = indexer_search(ip_query)

    top_ips = []

    for bucket in ip_data.get("aggregations", {}).get("top_attackers", {}).get("buckets", []):

        top_ips.append({
            "ip": bucket["key"],
            "count": bucket["doc_count"]
        })

    # -------------------------
    # TOP TARGETED AGENTS
    # -------------------------

    agent_query = {
        "size": 0,
        "aggs": {
            "top_agents": {
                "terms": {
                    "field": "agent.name",
                    "size": 5
                }
            }
        }
    }

    agent_data = indexer_search(agent_query)

    top_agents = []

    for bucket in agent_data.get("aggregations", {}).get("top_agents", {}).get("buckets", []):

        top_agents.append({
            "agent": bucket["key"],
            "count": bucket["doc_count"]
        })

    # -------------------------
    # ALERT ACTIVITY TIMELINE
    # -------------------------

    timeline_query = {
        "size": 0,
        "query": {
            "range": {
                "@timestamp": {
                    "gte": "now-7d",
                    "lte": "now"
                }
            }
        },
        "aggs": {
            "alerts_over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h"
                }
            }
        }
    }

    timeline_data = indexer_search(timeline_query)

    timeline_labels = []
    timeline_counts = []

    for bucket in timeline_data.get("aggregations", {}).get("alerts_over_time", {}).get("buckets", []):

        time_label = bucket["key_as_string"].split("T")[1][:5]

        timeline_labels.append(time_label)
        timeline_counts.append(bucket["doc_count"])

    # -------------------------
    # FINAL RETURN
    # -------------------------

    return {
        "low": low,
        "medium": medium,
        "high": high,
        "critical": critical,
        "total_alerts": total_alerts,
        "active_agents": active_agents,
        "offline_agents": offline_agents,
        "critical_alerts": recent_alerts,
        "top_ips": top_ips,
        "top_agents": top_agents,
        "timeline_labels": timeline_labels,
        "timeline_counts": timeline_counts
    }