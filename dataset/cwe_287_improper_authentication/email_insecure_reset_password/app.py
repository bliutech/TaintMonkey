from flask import Flask, request
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'

# Initialize Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Your email
app.config['MAIL_PASSWORD'] = 'your-app-password'
mail = Mail(app)

users = {
    "admin": {"password": "admin123", "email": "admin@gmail.com"},
    "audrey": {"password": "audrey123", "email": "audrey@gmail.com"},
    "sebastian": {"password": "sebastian123", "email": "sebastian@gmail.com"},
}

#Source
def get_email(this_request):
    return this_request.form.get("email")

#Sink
def send_simple_email(recipient, subject, body):
    try:
        msg = Message(
            subject=subject,
            sender=app.config['MAIL_USERNAME'],
            recipients=[recipient]
        )
        msg.body = body
        mail.send(msg) #Sink? May be more robust to make this a sink
        print(f"Email sent successfully to {recipient}")
    except Exception as e:
        print(f"Failed to send email: {e}")

@app.get("/reset_password")
def insecure_reset_passwrd_get():
    return '''
        <form method="post">
            <h2>Password Recover</h2>
            Username: <input name="username"><br>
            Recovery Email: <input name="email"><br>
            <input type="submit" value="Send">
        </form>
    '''

@app.post("/reset_password")
def insecure_reset_passwrd_post():
    username = request.form.get("username") #Also checks if user exists
    if username is None:
        return "This should not happen - no username"
    email = get_email(request) #Source
    if email is None:
        return "This should not happen - no email"

    send_simple_email(email, "Password Recovery", "IMAGINE RECOVERY CODE HERE") #Sink?

    return f"Email sent for {username}!"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080)