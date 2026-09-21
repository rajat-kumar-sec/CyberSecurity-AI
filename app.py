from flask import Flask, render_template_string, request
from analyzer import analyze_log

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>CyberSecurity AI</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #111827;
            color: white;
            max-width: 900px;
            margin: 40px auto;
            padding: 20px;
        }

        h1 {
            text-align: center;
        }

        textarea {
            width: 100%;
            height: 220px;
            padding: 12px;
            font-size: 15px;
            box-sizing: border-box;
        }

        button {
            margin-top: 15px;
            padding: 12px 25px;
            font-size: 16px;
            cursor: pointer;
        }

        .result {
            margin-top: 25px;
            padding: 20px;
            background: #1f2937;
            border-radius: 8px;
        }

        .high {
            color: #ff6b6b;
        }
    </style>
</head>

<body>

<h1>🛡️ CyberSecurity AI</h1>

<form method="POST">

    <textarea name="log" placeholder="Paste your security log here...">{{ log }}</textarea>

    <br>

    <button type="submit">Analyze Security Log</button>

</form>

{% if result %}

<div class="result">

    <h2>Security Analysis</h2>

    <p><b>Threat:</b> {{ result.threat_type }}</p>

    <p>
        <b>Risk:</b>
        <span class="high">{{ result.risk }}</span>
    </p>

    <h3>Evidence</h3>

    <p>Username: {{ result.username }}</p>
    <p>Source IP: {{ result.source_ip }}</p>
    <p>Attempts: {{ result.attempts }}</p>

    <h3>Findings</h3>

    <ul>
    {% for finding in result.findings %}
        <li>{{ finding }}</li>
    {% endfor %}
    </ul>

    <h3>Recommendations</h3>

    <ul>
    {% for recommendation in result.recommendations %}
        <li>{{ recommendation }}</li>
    {% endfor %}
    </ul>

</div>

{% endif %}

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


if __name__ == "__main__":
    app.run(debug=True)
