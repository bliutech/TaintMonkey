from flask import Flask, request, jsonify
import re

app = Flask(__name__)

ALLOWED_OPERATIONS = {
    "add": lambda x, y: x + y,
    "subtract": lambda x, y: x - y,
    "multiply": lambda x, y: x * y,
    "divide": lambda x, y: x / y if y != 0 else "Error: Division by zero",
    "power": lambda x, y: x**y,
    "square_root": lambda x: x**0.5
    if x >= 0
    else "Error: Cannot take square root of negative number",
}


@app.route("/execute", methods=["POST"])
def execute_handler():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"status": "error", "error": "Missing json data"}), 400

        if "operation" not in data:
            return jsonify({"status": "error", "error": "Missing operation field"}), 400

        operation = data["operation"]
        if operation not in ALLOWED_OPERATIONS:
            return jsonify(
                {
                    "status": "error",
                    "error": f"Invalid operation. Allowed operations: {', '.join(ALLOWED_OPERATIONS.keys())}",
                }
            ), 400

        if "values" not in data or not isinstance(data["values"], list):
            return jsonify(
                {"status": "error", "error": "Missing or invalid 'values' field"}
            ), 400

        values = data["values"]

        for val in values:
            if not isinstance(val, (int, float)):
                return jsonify(
                    {"status": "error", "error": "All values must be numbers"}
                ), 400

        if operation == "square_root":
            if len(values) != 1:
                return jsonify(
                    {
                        "status": "error",
                        "error": "Square root operation requires exactly 1 value",
                    }
                ), 400
            result = ALLOWED_OPERATIONS[operation](values[0])
        else:
            if len(values) != 2:
                return jsonify(
                    {"status": "error", "error": f"operation requires exactly 2 values"}
                ), 400
            result = ALLOWED_OPERATIONS[operation](values[0], values[1])

        return jsonify(
            {
                "status": "success",
                "operation": operation,
                "values": values,
                "result": result,
            }
        )

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
