from flask import Flask, request, jsonify

app = Flask(__name__)

def insecure_double_eval(expression):
    try:
        single_result = eval(expression)
        double_result = eval(single_result)
        return double_result
    except Exception as e:
        return "Error"
    
@app.route("/double-calculate")
def double_eval():
    expression = request.args.get("expr", "'2+2'")
    
    result = insecure_double_eval(expression)

    return jsonify({
        "expression": expression,
        "result": result
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
