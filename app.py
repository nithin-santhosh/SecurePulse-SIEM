from flask import Flask,request,jsonify ,render_template
from dotenv import load_dotenv
from services.incidents_service import fetch_incidents
from services.agents_service import fetch_agents
from services.alerts_service import fetch_alerts
from services.dashboard_service import fetch_dashboard_metrics
from services.logs_service import fetch_logs
from services.threat_intel_service import ThreatIntelService
from services.ai_service import ask_ai

load_dotenv()

app = Flask(__name__)

@app.context_processor
def inject_system_status():

    metrics = fetch_dashboard_metrics()

    if metrics["active_agents"] > 1 and metrics["total_alerts"] > 0:
        system_status = "Healthy"
    else:
        system_status = "Warning"

    return dict(system_status=system_status)

@app.route("/")
def dashboard():
    metrics = fetch_dashboard_metrics()

    # determine system status
    if metrics["active_agents"] > 1 and metrics["total_alerts"] > 0:
        system_status = "Healthy"
    else:
        system_status = "Warning"

    return render_template(
        "dashboard.html",
        metrics=metrics,
        system_status=system_status
    )


@app.route("/agents")
def agents():
    agents_data = fetch_agents()
    return render_template("agents.html", agents=agents_data)


@app.route("/alerts")
def alerts():
    alerts_data = fetch_alerts(limit=20)
    return render_template("alerts.html", alerts=alerts_data)

@app.route("/incidents")
def incidents():
    incidents_data = fetch_incidents()
    return render_template("incidents.html", incidents=incidents_data)

@app.route("/logs")
def logs():
    keyword = request.args.get("keyword")
    severity = request.args.get("severity")
    agent = request.args.get("agent")

    logs_data = fetch_logs(keyword, severity, agent)
    return render_template("logs.html", logs=logs_data)

@app.route("/threat-intel")
def threat_intel_page():
    return render_template("threat_intel.html")


@app.route("/api/threat-intel", methods=["POST"])
def threat_intel_api():
    data = request.get_json()
    ioc = data.get("ioc")

    if not ioc:
        return jsonify({"error": "IOC required"}), 400

    result = ThreatIntelService.lookup_ioc(ioc)
    return jsonify(result)

@app.route("/api/ai-analyst", methods=["POST"])
def ai_analyst():

    data = request.json
    question = data.get("question")

    answer = ask_ai(question)

    return jsonify({
        "response": answer
    })

@app.route("/ai-analyst")
def ai_page():
    return render_template("ai_analyst.html")

if __name__ == "__main__":
    app.run(debug=True)