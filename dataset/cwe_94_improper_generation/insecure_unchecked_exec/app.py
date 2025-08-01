from flask import Flask, request, jsonify
import json

app = Flask(__name__)

def execute_insecure(code_to_execute, local_vars=None):
    if local_vars is None:
        local_vars = {}

    exec(code_to_execute, {"__builtins__":__builtins__}, local_vars)

    serializable_vars = {}
    for key, value in local_vars.items():
        try:
            json.dumps(value)
            serializable_vars[key] = value
        except (TypeError, OverflowError):
            serializable_vars[key] = str(value)

    return serializable_vars

@app.route("/execute", methods=["POST"])
def execute_handler():
    try:
        data = request.get_json()

        if not data or "code" not in data:
            return jsonify({"error": "Missing code in json request"}), 400

        code_to_execute = data["code"]

        local_vars = {}
        if "variables" in data and isinstance(data["variables"], dict):
            local_vars = data["variables"]

        result = execute_insecure(code_to_execute, local_vars)
        return jsonify({"status": "success", "result": result})

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
