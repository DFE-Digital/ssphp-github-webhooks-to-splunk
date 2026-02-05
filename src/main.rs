#![feature(slice_pattern)]

mod hec_event;
mod service;
use crate::hec_event::HecEvent;
use crate::service::Service;
use axum::Json;
use axum::body::Bytes;
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header::HeaderMap},
    response::{IntoResponse, Response},
    routing::post,
};
use digest::MacError;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
type HmacSha256 = Hmac<Sha256>;
use azure_identity::DefaultAzureCredential;
use azure_identity::TokenCredentialOptions;
use azure_security_keyvault::KeyvaultClient;
use faster_hex::hex_decode;
use gethostname::gethostname;
use tracing::{error, info, warn};

struct Config {
    splunk_svc: Service,
    github_hmac_secret: Bytes,
}

#[tokio::main]
async fn main() {
    // Service Metadata
    let port = 443;
    let url = format!(
        "https://http-inputs-dfe.splunkcloud.com:{}/services/collector/event",
        port
    );

    let (token, github_hmac_secret) = get_secrets().await.expect("Failed to get Secrets");

    let config = Arc::new(Config {
        splunk_svc: Service::new(url, token),
        github_hmac_secret: Bytes::from_owner(github_hmac_secret),
    });

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let event_metadata = hec_event::EventMetaData::new(
        now,
        "ssphp_test".to_string(),
        "ssphp_github_webhooks_json".to_string(),
        "azure_webhooks_function".to_string(),
        gethostname().into_string().unwrap(),
    );
    let hec_event = HecEvent::new("Starting Sending GitHub Logs to Splunk", event_metadata);
    let serialized_event = serde_json::to_string(&hec_event).unwrap();
    config.splunk_svc.send_event(serialized_event).await;

    // build our application with a single route
    let app = Router::new()
        .route("/webhooks", post(root))
        .route("/test", post(test))
        .with_state(config);

    let port_key = "FUNCTIONS_CUSTOMHANDLER_PORT";
    let port: u16 = match std::env::var(port_key) {
        Ok(val) => val.parse().expect("Custom Handler port is not a number!"),
        Err(_) => 3000,
    };

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}

/// Health check
async fn test() -> Json<serde_json::Value> {
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

    let source_org = payload
        .get("organization")
        .and_then(|org| org.get("login"))
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| "no_org");
    let source_repo = payload
        .get("repository")
        .and_then(|org| org.get("name"))
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| "no_repo");
    let source_event = payload
        .get("headers")
        .and_then(|org| org.get("X-GitHub-Event"))
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| "no_event");
    let source_action = payload
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| "no_action");

    let event_metadata = hec_event::EventMetaData::new(
        now,
        "ssphp_test".to_string(),
        "ssphp_github_webhooks_json".to_string(),
        format!(
            "{}:{}:{}:{}",
            source_org, source_repo, source_event, source_action
        ),
        gethostname().into_string().unwrap(),
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

async fn get_secrets() -> Result<(String, String), Box<dyn std::error::Error>> {
    info!("Getting Default Azure Credentials");
    let credential = Arc::new(DefaultAzureCredential::create(
        TokenCredentialOptions::default(),
    )?);

    info!("KeyVault Secret Client created");
    let keyvault_name = std::env::var("KEY_VAULT_NAME").unwrap();
    let keyvault_url = format!("https://{keyvault_name}.vault.azure.net");
    let client = KeyvaultClient::new(&keyvault_url, credential.clone())?.secret_client();

    info!("KeyVault: getting '{}'", &"SPLUNK-HEC-TOKEN");
    let secret1 = client.get("SPLUNK-HEC-TOKEN").await?.value.to_string();

    info!("KeyVault: getting '{}'", &"GITHUB-HMAC-SECRET");
    let secret2 = client.get("GITHUB-HMAC-SECRET").await?.value.to_string();
    Ok((secret1, secret2))
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
