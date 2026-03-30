import os
from dotenv import load_dotenv
from groq import Groq
from wazuh_api import indexer_search

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def retrieve_alerts():

    query = {
        "size": 20,
        "query": {
            "range": {
                "timestamp": {
                    "gte": "now-24h"
                }
            }
        },
        "sort": [
            {"timestamp": {"order": "desc"}}
        ]
    }

    results = indexer_search(query)

    alerts = []

    for hit in results.get("hits", {}).get("hits", []):
        src = hit["_source"]

        alert = {
            "agent": src.get("agent", {}).get("name"),
            "rule": src.get("rule", {}).get("description"),
            "level": src.get("rule", {}).get("level"),
            "time": src.get("timestamp")
        }

        alerts.append(alert)

    return alerts


def ask_ai(question):

    alerts = retrieve_alerts()

    context = ""

    for a in alerts:
        context += f"""
Agent: {a['agent']}
Rule: {a['rule']}
Level: {a['level']}
Time: {a['time']}
"""

    prompt = f"""
You are a SOC analyst for SecurePulse SIEM.

Analyze the following security alerts and answer the user's question.

Alerts:
{context}

Question:
{question}

Focus on security-relevant behavior such as:
- authentication failures
- privilege escalation attempts
- suspicious process execution
- repeated login attempts
- unusual system activity
- service start/stop anomalies

If possible, identify:
- suspicious hosts
- repeated attack patterns
- potential security risks

Respond in this format:

Summary
- key finding
- key finding

Important Events
- event description
- event description

Rules for formatting:
- Use plain text only.
- Do NOT use markdown symbols like ** or *.
- Use simple bullet points starting with "-".
- Keep the response short and readable.
"""

    completion = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}]
    )

    return completion.choices[0].message.content