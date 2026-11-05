from flask import Flask, render_template, request, jsonify
from analyzer import analyze_log

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    log = ""

    if request.method == "POST":

        log = request.form.get("log", "")

        if log.strip():
            result = analyze_log(log)

    return render_template(
        "index.html",
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
