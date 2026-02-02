#![feature(slice_pattern)]

mod hec_event;
mod service;
mod azure_request_response;
use crate::azure_request_response::{ AzureInvokeRequest, AzureInvokeResponse };
use crate::service::Service;

use crate::hec_event::HecEvent;
use axum::Json;
use axum::body::Bytes;
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header::HeaderMap},
    response::{IntoResponse, Response},
    routing::{post, get},
};
use digest::MacError;
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;
use faster_hex::hex_decode;
struct Config {
    splunk_svc: Service,
    github_hmac_secret: Bytes,
}

#[tokio::main]
async fn main() {
    // Service Metadata
    let port = 8088;
    let url = format!("http://localhost:{}/services/collector/event", port);
    // let token = std::env::var("SPLUNK_HEC_TOKEN").unwrap();
    // let github_hmac_secret = std::env::var("GITHUB_WEBHOOK_SECRET").unwrap();
    let token = "foo".to_string();
    let github_hmac_secret = "bar".to_string();

    let config = Arc::new(Config {
        splunk_svc: Service::new(url, token),
        github_hmac_secret: Bytes::from_owner(github_hmac_secret),
    });

    // build our application with a single route
    let app = Router::new()
            .route("/webhooks", post(root))
            .route("/test", post(get_root))
            .with_state(config);

    // run our app with hyper, listening globally on port 3000
    // let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();


    let port_key = "FUNCTIONS_CUSTOMHANDLER_PORT";
    let port: u16 = match std::env::var(port_key) {
        Ok(val) => val.parse().expect("Custom Handler port is not a number!"),
        Err(_) => 3000,
    };

    // info!(name = name, port = port);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await.unwrap();
        // .context("Binding to socket")?;
    // let axum_serve = axum::serve(listener, app);

    axum::serve(listener, app).await.unwrap();
}



/// Health check
async fn get_root(headers: HeaderMap) -> Json<serde_json::Value> {
    // trace!("root request");
    // Json(AzureInvokeResponse {
    //     outputs: None,
    //     logs: vec![
    //         "GET /".to_string(),
    //         format!("Headers: {:?}", headers),
    //     ],
    //     return_value: Some(json!(200))
    // })
    json!({"Outputs": {"res": {"body": "{0:1}"}}, "Logs": null, "ReturnValue": null}).into()
}




async fn root(State(config): State<Arc<Config>>, headers: HeaderMap, body: Bytes) -> Response {
    match validate_webhook_payload(&config.github_hmac_secret, &headers, &body) {
        Ok(_) => (),
        Err(err) => {
            dbg!("!!!INVALID!!!");
            dbg!(err);
            dbg!(&headers);
            let bad_json_string = String::from_utf8(body.to_vec()).unwrap();
            dbg!(bad_json_string);
            return StatusCode::BAD_REQUEST.into_response();
        }
    }

    let msg_headers = [
        "X-GitHub-Delivery",
        "X-Hub-Signature",
        "X-Hub-Signature-256",
        "X-GitHub-Event",
        "X-GitHub-Hook-ID",
        "X-GitHub-Hook-Installation-Target-ID",
        "X-GitHub-Hook-Installation-Target-Type",
    ];
    let mut headers_values = serde_json::Map::new();

    for msg_header in msg_headers {
        let Some(value) = headers.get(msg_header) else {
            continue;
        };
        let Ok(value) = value.to_str() else {
            continue;
        };
        headers_values.insert(msg_header.into(), value.to_string().into());
    }

    let mut payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(err) => {
            dbg!(err);
            let bad_json_string = String::from_utf8(body.to_vec()).unwrap();
            dbg!(bad_json_string);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    if let Some(payload) = payload.as_object_mut() {
        payload.insert("headers".to_string(), headers_values.into());
    } else {
        return (StatusCode::BAD_REQUEST).into_response();
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let event_metadata = hec_event::EventMetaData::new(
        now,
        "main".to_string(),
        "ssphp_github".to_string(),
        "ssphp_github".to_string(),
        "ssphp_github".to_string(),
    );
    let hec_event = HecEvent::new(payload, event_metadata);
    let serialized_event = serde_json::to_string(&hec_event).unwrap();
    config.splunk_svc.send_event(serialized_event).await;

    StatusCode::OK.into_response()
}

fn validate_webhook_payload(
    secret: &Bytes,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(), ValidationError> {
    let Some(github_hash) = headers.get("x-hub-signature-256") else {
        return Err(ValidationError::MissingHeader);
    };
    let github_hash = github_hash
        .to_str()
        .unwrap()
        .split('=')
        .next_back()
        .unwrap()
        .as_bytes();

    let mut hash_bytes = vec![0; github_hash.len() / 2];

    hex_decode(github_hash, &mut hash_bytes)?;

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");

    mac.update(body);

    mac.verify_slice(&hash_bytes[..])?;
    Ok(())
}

#[derive(Debug, Clone)]
enum ValidationError {
    MacError(MacError),
    MissingHeader,
    #[allow(dead_code)]
    FasterHex(faster_hex::Error),
}

impl From<faster_hex::Error> for ValidationError {
    fn from(value: faster_hex::Error) -> Self {
        ValidationError::FasterHex(value)
    }
}

impl From<digest::MacError> for ValidationError {
    fn from(value: digest::MacError) -> Self {
        ValidationError::MacError(value)
    }
}
