import os
import requests

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"


class ThreatIntelService:

    @staticmethod
    def lookup_ioc(ioc):
        if not VT_API_KEY:
            return {"error": "VirusTotal API key not configured"}

        headers = {"x-apikey": VT_API_KEY}

        # Determine IOC type
        if len(ioc) in [32, 40, 64]:
            url = f"{VT_BASE}/files/{ioc}"
        elif "." in ioc and not ioc.replace(".", "").isdigit():
            url = f"{VT_BASE}/domains/{ioc}"
        else:
            url = f"{VT_BASE}/ip_addresses/{ioc}"

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            return {"error": "Lookup failed", "details": response.text}

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation", 0),
            "last_analysis_date": attributes.get("last_analysis_date")
        }