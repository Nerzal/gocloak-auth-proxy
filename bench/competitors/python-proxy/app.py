import contextlib
import json
import os
import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

ISSUER = os.environ["ISSUER"].rstrip("/")
AUDIENCE = os.environ["AUDIENCE"]
UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "").rstrip("/")

KEYS = {}
CLIENT: httpx.AsyncClient | None = None


@contextlib.asynccontextmanager
async def lifespan(_app):
    global CLIENT
    CLIENT = httpx.AsyncClient(
        limits=httpx.Limits(max_connections=256, max_keepalive_connections=256),
        timeout=5.0,
        trust_env=False,
    )
    resp = await CLIENT.get(f"{ISSUER}/protocol/openid-connect/certs")
    resp.raise_for_status()
    for jwk in resp.json().get("keys", []):
        if jwk.get("kty") == "RSA" and jwk.get("kid"):
            KEYS[jwk["kid"]] = RSAAlgorithm.from_jwk(json.dumps(jwk))
    try:
        yield
    finally:
        await CLIENT.aclose()


async def healthz(_request: Request):
    return Response(status_code=200)


async def proxy_handler(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return Response(status_code=401)
    token = auth[7:]
    try:
        hdr = jwt.get_unverified_header(token)
        key = KEYS.get(hdr.get("kid"))
        if key is None:
            return Response(status_code=401)
        claims = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
        )
        if claims.get("typ") != "Bearer":
            return Response(status_code=401)
    except Exception:
        return Response(status_code=401)

    user = claims.get("preferred_username") or claims.get("sub") or ""
    email = claims.get("email") or ""
    roles = ",".join(claims.get("realm_access", {}).get("roles", []))

    if UPSTREAM_URL:
        url = f"{UPSTREAM_URL}{request.url.path}"
        up_resp = await CLIENT.get(
            url,
            headers={
                "X-Auth-Request-User": user,
                "X-Auth-Request-Email": email,
                "X-Auth-Request-Roles": roles,
            },
        )
        return Response(content=up_resp.content, status_code=up_resp.status_code)

    return Response(
        status_code=200,
        headers={
            "X-Auth-Request-User": user,
            "X-Auth-Request-Email": email,
            "X-Auth-Request-Roles": roles,
            "Cache-Control": "no-store",
        },
    )


app = Starlette(
    routes=[
        Route("/healthz", healthz, methods=["GET"]),
        Route("/{path:path}", proxy_handler, methods=["GET", "POST", "PUT", "DELETE"]),
        Route("/", proxy_handler, methods=["GET", "POST", "PUT", "DELETE"]),
    ],
    lifespan=lifespan,
)
