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

def execute_secure(operation, values):
    if operation not in ALLOWED_OPERATIONS:
        return None, f"Invalid operation. Allowed operations: {', '.join(ALLOWED_OPERATIONS.keys())}", 400

    if not isinstance(values, list):
        return None, "Missing or invalid 'values' field", 400
    
    for val in values:
        if not isinstance(val, (int, float)):
            return None, "All values must be numbers", 400

    try:
        if operation == "square_root":
            if len(values) != 1:
                return None, "Square root operation requires exactly 1 value", 400
            result = ALLOWED_OPERATIONS[operation](values[0])
        else:
            if len(values) != 2:
                return None, f"Operation requires exactly 2 values", 400
            result = ALLOWED_OPERATIONS[operation](values[0], values[1])
        
        return result, None, None
    except Exception as e:
        return None, str(e), 500

@app.route("/execute", methods=["POST"])
def execute_handler():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"status": "error", "error": "Missing json data"}), 400

        if "operation" not in data:
            return jsonify({"status": "error", "error": "Missing operation field"}), 400

        operation = data["operation"]
        
        if "values" not in data:
            return jsonify({"status": "error", "error": "Missing 'values' field"}), 400
            
        values = data["values"]
        
        result, error, status_code = execute_secure(operation, values)
        
        if error:
            return jsonify({"status": "error", "error": error}), status_code
        
        return jsonify({
            "status": "success",
            "operation": operation,
            "values": values,
            "result": result,
        })

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
