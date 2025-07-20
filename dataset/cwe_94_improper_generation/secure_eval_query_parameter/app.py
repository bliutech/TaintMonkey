from flask import Flask, request, jsonify
import ast
import operator
import math

app = Flask(__name__)


class MathExpressionEvaluator(ast.NodeVisitor):
    ALLOWED_OPERATORS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.Pow: operator.pow,
        ast.USub: operator.neg,
    }

    ALLOWED_FUNCTIONS = {
        "sqrt": math.sqrt,
        "sin": math.sin,
        "cos": math.cos,
        "tan": math.tan,
        "abs": abs,
        "log": math.log,
    }

    def __init__(self):
        self.max_operations = 100
        self.operation_count = 0

    def check_math_operation(self, node):
        self.operation_count += 1
        if self.operation_count > self.max_operations:
            raise ValueError("Expression too complex")

        if type(node.op) not in self.ALLOWED_OPERATORS:
            raise ValueError(f"Unsupported operator")

        left = self.visit(node.left)
        right = self.visit(node.right)

        if isinstance(node.op, ast.Div) and right == 0:
            raise ValueError("Can't devide by zero")
        if isinstance(node.op, ast.Pow):
            if right > 100:
                raise ValueError("Exponent too large")
            if left > 1000:
                raise ValueError("Base too large")

        return self.ALLOWED_OPERATORS[type(node.op)](left, right)

    def check_math_function(self, node):
        if not isinstance(node.func, ast.Name):
            raise ValueError("Invalid function")

        func_name = node.func.id
        if func_name not in self.ALLOWED_FUNCTIONS:
            raise ValueError(f"Unsupported function")

        args = [self.visit(arg) for arg in node.args]

        if func_name == "sqrt" and args[0] < 0:
            raise ValueError("Square root of negative number")
        if func_name == "log" and args[0] <= 0:
            raise ValueError("Log of non-positive number")

        return self.ALLOWED_FUNCTIONS[func_name](*args)

    def check_number(self, node):
        if isinstance(node, ast.Num):
            value = node.n
        elif isinstance(node, ast.Constant):
            value = node.value
        else:
            raise ValueError("Invalid number type")

        if not isinstance(value, (int, float)):
            raise ValueError("Only numbers allowed")
        if abs(value) > 1e10:
            raise ValueError("Number too large")
        return value

    def check_math_constant(self, node):
        if node.id == "pi":
            return math.pi
        if node.id == "e":
            return math.e
        raise ValueError(f"Unknown variable")

    def check_negative_number(self, node):
        if not isinstance(node.op, ast.USub):
            raise ValueError("Unsupported opperator")
        return -self.visit(node.operand)

    visit_BinOp = check_math_operation
    visit_Call = check_math_function
    visit_Constant = check_number
    visit_Num = check_number
    visit_Name = check_math_constant
    visit_UnaryOp = check_negative_number

    def generic_visit(self, node):
        raise ValueError(f"Unsupported expression")


def evaluate_math_expression(expression: str) -> float:
    try:
        tree = ast.parse(expression, mode="eval")
        evaluator = MathExpressionEvaluator()
        result = evaluator.visit(tree.body)

        if not isinstance(result, (int, float)):
            raise ValueError("Result must be a number")

        return result
    except Exception as e:
        raise ValueError(f"Invalid expression")


@app.route("/calculate")
def calculate():
    expression = request.args.get("expr", "2+2")

    try:
        result = evaluate_math_expression(expression)
        return jsonify(
            {"expression": expression, "result": result, "status": "success"}
        )
    except ValueError as e:
        return jsonify(
            {"expression": expression, "error": str(e), "status": "error"}
        ), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
