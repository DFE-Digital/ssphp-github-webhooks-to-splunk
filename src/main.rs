mod hec_event;
mod service;
use crate::service::Service;

use crate::hec_event::HecEvent;
use axum::{
    Router,
    extract::Json,
    extract::State,
    http::{StatusCode, header::HeaderMap},
    response::{IntoResponse, Response},
    routing::post,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() {
    // Service Metadata
    let port = 443;
    let url = format!(
        "https://http-inputs-dfe.splunkcloud.com:{}/services/collector/event",
        port
    );
    let token = std::env::var("SPLUNK_HEC_TOKEN").unwrap();
    let svc = Arc::new(Service::new(url, token));

    // build our application with a single route
    let app = Router::new()
        .route("/", post(root))
        .route("/foo", post(post_foo))
        .with_state(svc);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root(
    State(splunk_svc): State<Arc<Service>>,
    headers: HeaderMap,
    Json(mut payload): Json<serde_json::Value>,
) -> Response {
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

    println!("header object : {:#?} ", headers_values);

    if let Some(payload) = payload.as_object_mut() {
        payload.insert("headers".to_string(), headers_values.into());
    } else {
        return (StatusCode::BAD_REQUEST).into_response();
    };

    println!("payload : {} ", payload);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let event_metadata = hec_event::EventMetaData::new(
        now,
        "ssphp_test".to_string(),
        "ssphp_github".to_string(),
        "ssphp_github".to_string(),
        "ssphp_github".to_string(),
    );
    let hec_event = HecEvent::new(payload, event_metadata);
    let serialized_event = serde_json::to_string(&hec_event).unwrap();
    splunk_svc.send_event(serialized_event).await;

    StatusCode::OK.into_response()
}

async fn post_foo() {}
