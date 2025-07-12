from flask import Flask, request
from sqlalchemy import text
from db import db, init_db

app = Flask(__name__)
init_db(app)

@app.route('/secure-second-level', methods=['GET'])
def secure_second_level():
    username = request.args.get('username')
    
    if not username:
        return "Username is required", 400
    
    # second-level, getting from database when needed level, takes full string as a string rather 
    query = text(f"SELECT * FROM user WHERE username = :username")
    
    try:
        result = db.session.execute(query, {"username": username}).fetchall()
        if result:
            # system works to not run sql command and properly find users
            return f"Found others with similar usernames", 200
        return "No users found", 404
    except Exception as e:
        return f"Error: {str(e)}", 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8080)