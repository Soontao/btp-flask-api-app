from flask import Flask, request, g
from sap import xssec
from sap.cf_logging import flask_logging
from cfenv import AppEnv
import logging

app = Flask(__name__)
app.config.from_prefixed_env()
flask_logging.init(app, logging.INFO)
env = AppEnv()


if app.config.get("ENV") != "production":
    logging.info("authentication enabled")

    @app.before_request
    def authentication():
        uaa_service = env.get_service(label="xsuaa")
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return {"error": "Token is missing"}, 401

        # Extract the token from the Authorization header
        try:
            token_type, token = auth_header.split(" ")
            if token_type.lower() != "bearer":
                raise ValueError("Invalid token type")
        except ValueError:
            return {"error": "Invalid token format"}, 401

        g.security_context = xssec.create_security_context(
            token, uaa_service.credentials
        )


@app.route("/")
def index():
    return "Hello, World!"
