from flask import Flask, render_template_string, request, jsonify
from analyzer import analyze_log

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>CyberSecurity AI - SOC Dashboard</title>

    <style>
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #0f172a;
            color: #e5e7eb;
        }

        .header {
            background: #111827;
            padding: 25px;
            text-align: center;
            border-bottom: 1px solid #374151;
        }

        .header h1 {
            margin: 0;
        }

        .header p {
            color: #9ca3af;
        }

        .container {
            max-width: 1100px;
            margin: 30px auto;
            padding: 20px;
        }

        textarea {
            width: 100%;
            height: 220px;
            box-sizing: border-box;
            padding: 15px;
            background: #020617;
            color: #e5e7eb;
            border: 1px solid #374151;
            border-radius: 8px;
            font-size: 15px;
            resize: vertical;
        }

        button {
            margin-top: 15px;
            padding: 12px 25px;
            background: #2563eb;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
        }

        button:hover {
            background: #1d4ed8;
        }

        .dashboard {
            margin-top: 30px;
        }

        .cards {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
        }

        .card {
            background: #1e293b;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #334155;
        }

        .card-title {
            color: #94a3b8;
            font-size: 14px;
        }

        .card-value {
            margin-top: 8px;
            font-size: 22px;
            font-weight: bold;
        }

        .risk-high {
            color: #ef4444;
        }

        .risk-medium {
            color: #f59e0b;
        }

        .risk-low {
            color: #22c55e;
        }

        .section {
            background: #1e293b;
            margin-top: 20px;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #334155;
        }

        li {
            margin: 8px 0;
        }

        @media (max-width: 700px) {
            .cards {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>

<body>

<div class="header">
    <h1>🛡️ CyberSecurity AI</h1>
    <p>SOC Analysis Dashboard</p>
</div>

<div class="container">

    <h2>Security Log Analysis</h2>

    <form method="POST">

        <textarea name="log"
            placeholder="Paste security logs here...">{{ log }}</textarea>

        <br>

        <button type="submit">Analyze Security Log</button>

    </form>

    {% if result %}

    <div class="dashboard">

        <div class="cards">

            <div class="card">
                <div class="card-title">THREAT</div>
                <div class="card-value">
                    {{ result.threat_type }}
                </div>
            </div>

            <div class="card">
                <div class="card-title">RISK LEVEL</div>

                <div class="card-value
                    {% if result.risk == 'HIGH' %}
                        risk-high
                    {% elif result.risk == 'MEDIUM' %}
                        risk-medium
                    {% else %}
                        risk-low
                    {% endif %}
                ">
                    {{ result.risk }}
                </div>
            </div>

            <div class="card">
                <div class="card-title">SOURCE IP</div>
                <div class="card-value">
                    {{ result.source_ip }}
                </div>
            </div>

        </div>

        <div class="section">

            <h2>Evidence</h2>

            <p>
                <b>Username:</b>
                {{ result.username }}
            </p>

            <p>
                <b>Source IP:</b>
                {{ result.source_ip }}
            </p>

            <p>
                <b>Attempts:</b>
                {{ result.attempts }}
            </p>

        </div>

        <div class="section">

            <div class="section">

        <h2>🤖 Machine Learning Analysis</h2>

        <p>
            <b>ML Prediction:</b>
            {{ result.ml_prediction }}
        </p>

        <p>
            <b>ML Confidence:</b>
            {{ (result.ml_confidence * 100) | round(2) }}%
        </p>

    </div>

    <h2>🔎 Findings</h2>

            <ul>
            {% for finding in result.findings %}
                <li>{{ finding }}</li>
            {% endfor %}
            </ul>

        </div>

        <div class="section">

            <h2>🛠️ Recommended Actions</h2>

            <ul>
            {% for recommendation in result.recommendations %}
                <li>{{ recommendation }}</li>
            {% endfor %}
            </ul>

        </div>

    </div>

    {% endif %}

</div>

</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    log = ""

    if request.method == "POST":

        log = request.form.get("log", "")

        if log.strip():
            result = analyze_log(log)

    return render_template_string(
        HTML,
        result=result,
        log=log
    )


@app.route("/api/analyze", methods=["POST"])
def api_analyze():

    data = request.get_json(silent=True)

    if not data or "log" not in data:
        return jsonify({
            "error": "Please provide a 'log' field."
        }), 400

    log = data["log"]

    if not isinstance(log, str) or not log.strip():
        return jsonify({
            "error": "Log must be a non-empty string."
        }), 400

    result = analyze_log(log)

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
