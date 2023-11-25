from sanic import Request, Sanic, text, json
from sanic.exceptions import SanicException, Unauthorized
from sap import xssec
from sap.cf_logging import sanic_logging
from cfenv import AppEnv
from sanic.log import logger

env = AppEnv()
app = Sanic(env.name if env.name else "app")
app.config.FALLBACK_ERROR_FORMAT = "json"
is_prod = app.config.get("ENV") == "production"

if is_prod:
    sanic_logging.init(app)
    logger.info("cf logging enabled")


if is_prod:
    logger.info("authentication enabled")

    @app.on_request
    def authentication(request: Request):
        uaa_service = env.get_service(label="xsuaa")
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            raise Unauthorized("Token is missing")

        token_type, token = auth_header.split(" ")
        if token_type.lower() != "bearer":
            raise Unauthorized("Invalid token type")

        app.ctx.security_context = xssec.create_security_context(
            token, uaa_service.credentials
        )


@app.route("/")
def index(request):
    return json({"msg": "Hello BTP!"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
