use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Request, Response, StatusCode},
    routing::any,
    Router,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::{collections::HashMap, env, sync::Arc};

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Deserialize)]
struct RealmAccess {
    #[serde(default)]
    roles: Vec<String>,
}

#[derive(Deserialize)]
struct Claims {
    #[serde(default)]
    typ: String,
    #[serde(default)]
    sub: String,
    #[serde(default)]
    preferred_username: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    realm_access: Option<RealmAccess>,
}

struct AppState {
    keys: HashMap<String, DecodingKey>,
    validation: Validation,
    upstream: Option<String>,
    client: reqwest::Client,
}

async fn handle(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response<Body> {
    let auth = match req.headers().get("authorization").and_then(|v| v.to_str().ok()) {
        Some(v) => v,
        None => return Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap(),
    };
    let token = match auth.strip_prefix("Bearer ") {
        Some(t) if !t.is_empty() => t,
        _ => return Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap(),
    };
    let header = match decode_header(token) {
        Ok(h) => h,
        Err(_) => return Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap(),
    };
    let key = match header.kid.as_deref().and_then(|k| state.keys.get(k)) {
        Some(k) => k,
        None => return Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap(),
    };
    let data = match decode::<Claims>(token, key, &state.validation) {
        Ok(d) => d.claims,
        Err(_) => return Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap(),
    };
    if data.typ != "Bearer" {
        return Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap();
    }
    let user = if !data.preferred_username.is_empty() {
        data.preferred_username
    } else {
        data.sub
    };
    let roles = data
        .realm_access
        .map(|r| r.roles.join(","))
        .unwrap_or_default();

    if let Some(upstream) = &state.upstream {
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let url = format!("{}{}", upstream, path);
        let mut up_headers = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&user) {
            up_headers.insert("x-auth-request-user", v);
        }
        if let Ok(v) = HeaderValue::from_str(&data.email) {
            up_headers.insert("x-auth-request-email", v);
        }
        if let Ok(v) = HeaderValue::from_str(&roles) {
            up_headers.insert("x-auth-request-roles", v);
        }
        match state.client.get(url).headers(up_headers).send().await {
            Ok(resp) => {
                let status = resp.status();
                let bytes = resp.bytes().await.unwrap_or_default();
                Response::builder()
                    .status(status)
                    .body(Body::from(bytes))
                    .unwrap()
            }
            Err(_) => Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::empty())
                .unwrap(),
        }
    } else {
        let mut resp = Response::builder().status(StatusCode::OK);
        resp = resp
            .header("x-auth-request-user", user)
            .header("x-auth-request-email", data.email)
            .header("x-auth-request-roles", roles)
            .header("cache-control", "no-store");
        resp.body(Body::empty()).unwrap()
    }
}

#[tokio::main]
async fn main() {
    let issuer = env::var("ISSUER").expect("ISSUER required");
    let audience = env::var("AUDIENCE").expect("AUDIENCE required");
    let listen = env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:18090".to_string());
    let upstream = env::var("UPSTREAM_URL").ok().filter(|s| !s.is_empty());

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(256)
        .build()
        .unwrap();

    let jwks_url = format!("{}/protocol/openid-connect/certs", issuer.trim_end_matches('/'));
    let jwks: Jwks = client.get(&jwks_url).send().await.unwrap().json().await.unwrap();
    let mut keys = HashMap::new();
    for k in jwks.keys {
        if let Ok(dk) = DecodingKey::from_rsa_components(&k.n, &k.e) {
            keys.insert(k.kid, dk);
        }
    }

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);

    let state = Arc::new(AppState {
        keys,
        validation,
        upstream,
        client,
    });

    let app = Router::new()
        .route("/healthz", any(|| async { StatusCode::OK }))
        .fallback(any(handle))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
