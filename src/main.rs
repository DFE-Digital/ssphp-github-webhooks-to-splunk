#![feature(str_as_str)]
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
use serde_json::{Map, json};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
type HmacSha256 = Hmac<Sha256>;
use anyhow::{Context, Result};
use azure_identity::DefaultAzureCredential;
use azure_identity::TokenCredentialOptions;
use azure_security_keyvault::KeyvaultClient;
use data_ingester_github::OctocrabGit;
use data_ingester_supporting::keyvault::GitHubApp;
use faster_hex::hex_decode;
use futures_util::TryStreamExt;
use gethostname::gethostname;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tokio::pin;
use tracing::info;

struct Config {
    splunk_svc: Service,
    github_hmac_secret: Bytes,
    github_clients: GitHubClients,
    hostname: String,
}

struct GitHubClients(HashMap<String, OctocrabGit>);

async fn get_github_installations(github_app: GitHubApp) -> Result<GitHubClients> {
    let client = OctocrabGit::new_from_app(&github_app)?;

    info!("Getting installations");
    let installations = client
        .client
        .apps()
        .installations()
        .send()
        .await
        .context("Getting installations for github app")?;

    let mut clients: HashMap<String, OctocrabGit> = HashMap::new();

    for installation in installations {
        info!("Installation ID: {}", installation.id);
        if installation.account.r#type != "Organization" {
            continue;
        }
        let installation_client = client
            .for_installation_id(installation.id)
            .await
            .context("build octocrabgit client")?;
        let org_name = installation.account.login.to_string();
        clients.insert(org_name, installation_client);
    }
    Ok(GitHubClients(clients))
}

#[tokio::main]
async fn main() {
    // Service Metadata
    let port = 443;
    let url = format!(
        "https://http-inputs-dfe.splunkcloud.com:{}/services/collector/event",
        port
    );

    let app_secrets = get_secrets().await.expect("Failed to get Secrets");

    let github_app = GitHubApp::new(app_secrets.github_app_id, app_secrets.github_app_secret)
        .expect("GitHub app should build");
    let github_clients = get_github_installations(github_app)
        .await
        .expect("Need to get github installations");

    let config = Arc::new(Config {
        splunk_svc: Service::new(url, app_secrets.token),
        github_hmac_secret: Bytes::from_owner(app_secrets.github_hmac_secret),
        github_clients,
        hostname: gethostname()
            .into_string()
            .expect("must be able to get hostname"),
    });

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Must be able to get system time")
        .as_secs() as usize;

    let event_metadata = hec_event::EventMetaData::new(
        now,
        "github".to_string(),
        "github_json".to_string(),
        "azure_webhooks_function".to_string(),
        config.hostname.to_string(),
    );

    let hec_event = HecEvent::new("Starting Sending GitHub Logs to Splunk", event_metadata);
    let serialized_event =
        serde_json::to_string(&hec_event).expect("Must be able to serialize startup event");
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
        .expect("Can't bind to port");

    axum::serve(listener, app)
        .await
        .expect("Can't start axum server");
}

/// Health check
async fn test() -> Json<serde_json::Value> {
    json!({"Outputs": {"res": {"body": "{0:1}"}}, "Logs": null, "ReturnValue": null}).into()
}

#[derive(Deserialize, Debug)]
struct SecretAlert<'a> {
    action: &'a str,
    alert: SecretAlertAlert,
    organization: Organization<'a>,
    repository: Repository<'a>,
    //location: Location,
    //sender: (),
}

#[derive(Deserialize, Debug)]
struct SecretAlertAlert {
    number: u32,
}

// #[derive(Deserialize, Debug)]
// struct SecretAlertLocation<'a> {
//     action: &'a str,
//     //alert: (),
//     organization: Organization<'a>,
//     repository: Repository<'a>,
//     location: Location,
//     //sender: (),
// }

#[derive(Deserialize, Debug)]
struct Repository<'a> {
    //    full_name: &'a str,
    name: &'a str,
}

#[derive(Deserialize, Debug)]
struct Organization<'a> {
    login: &'a str,
}

async fn github_secret_alert(
    payload_in: &Bytes,
    payload_out: &mut Value,
    github_clients: &GitHubClients,
) -> Result<()> {
    let secret_alert: SecretAlert = serde_json::from_slice(payload_in)?;

    let github_client = github_clients
        .0
        .get(secret_alert.organization.login)
        .context("don't have Octobrab client for this GitHub Org")?;

    let stream = github_client
        .client
        .repos(
            secret_alert.organization.login,
            secret_alert.repository.name,
        )
        .secrets_scanning()
        .get_alert_locations(secret_alert.alert.number)
        .await
        .context("Getting secret alert location")?
        .into_stream(&github_client.client);

    pin!(stream);

    let mut locations = Vec::new();
    while let Ok(Some(secret_location)) = stream.try_next().await {
        //dbg!(&secret_location.commit_sha);
        let sha = match &secret_location {
            octocrab::models::repos::secret_scanning_alert::SecretsScanningAlertLocation::Commit{commit_sha, ..} => Some(commit_sha),
            _ => None
        };

        if let Some(sha) = sha {
            let commit = github_client
                .client
                .repos(
                    secret_alert.organization.login,
                    secret_alert.repository.name,
                )
                .list_commits()
                .sha(sha)
                .per_page(1)
                .send()
                .await
                .context("Getting SHA for secret commit")?
                .items
                .first()
                .context("No commit found for commit SHA")?
                .clone();
            let mut map = Map::new();
            let mut author_set = HashSet::new();
            map.insert("commit_sha".to_string(), Value::String(sha.to_string()));
            if let Some(author) = &commit.author.as_ref().map(|author| author.login.as_str()) {
                map.insert("author".to_string(), Value::String(author.to_string()));
                author_set.insert(author.to_string());
            }
            if let Some(committer) = commit
                .committer
                .as_ref()
                .map(|committer| committer.login.as_str())
            {
                map.insert(
                    "committer".to_string(),
                    Value::String(committer.to_string()),
                );
                author_set.insert(committer.to_string());
            }
            locations.push((map, author_set));
        }
    }

    let mut ssphp = Map::new();
    ssphp.insert(
        "committers".to_string(),
        locations
            .iter()
            .flat_map(|location| location.1.iter())
            .map(|author| author.to_string())
            .collect::<Vec<String>>()
            .into(),
    );

    ssphp.insert(
        "secret_locations".to_string(),
        locations
            .into_iter()
            .map(|location| location.0)
            .collect::<Vec<Map<String, Value>>>()
            .into(),
    );

    payload_out
        .as_object_mut()
        .and_then(|obj| obj.insert("SSPHP".to_string(), Value::Object(ssphp)));
    Ok(())
}

// async fn github_secret_alert_location(
//     payload_in: &Bytes,
//     payload_out: &mut Value,
//     github_clients: &GitHubClients,
// ) {
//     let secret_alert_location: SecretAlertLocation = serde_json::from_slice(payload_in).unwrap();
//     dbg!(&secret_alert_location);
//     let url = format!(
//         "https://api.github.com/repos/{}/{}/commits/{}",
//         secret_alert_location.organization.login,
//         secret_alert_location.repository.name,
//         secret_alert_location.location.details.commit_sha,
//     );
//     dbg!(&url);
//     let client = reqwest::Client::new();
//     let result = client
//         .get(url)
//         .header("user-agent", "githubwebhooksappthing")
//         .header("Accept", "application/vnd.github+json")
//         .header("X-GitHub-Api-Version", "2022-11-28")
//         .send()
//         .await
//         .unwrap();
//     let body = result.bytes().await.unwrap();
//     let json: GitHubCommit = serde_json::from_slice(&body.as_slice()).unwrap();
//     let mut ssphp = Map::new();
//     ssphp.insert("committer".to_string(), json.committer.login.into());
//     ssphp.insert("author".to_string(), json.author.login.into());
//     payload_out
//         .as_object_mut()
//         .and_then(|obj| obj.insert("SSPHP".to_string(), Value::Object(ssphp)));
// }

async fn root(State(config): State<Arc<Config>>, headers: HeaderMap, body: Bytes) -> Response {
    match validate_webhook_payload(&config.github_hmac_secret, &headers, &body) {
        Ok(_) => (),
        Err(err) => {
            dbg!(&err);
            dbg!(&headers);
            let bad_json_string = String::from_utf8(body.to_vec())
                .unwrap_or_else(|_| "Unable to decode request body as UTF-8".to_string());
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
            let bad_json_string = String::from_utf8(body.to_vec())
                .unwrap_or_else(|_| "Unable to decode request body as UTF-8".to_string());
            dbg!(bad_json_string);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    match headers
        .get("X-GitHub-Event")
        .map(|header_value| header_value.to_str())
    {
        Some(Ok("secret_scanning_alert")) => {
            let _unused_result =
                github_secret_alert(&body, &mut payload, &config.github_clients).await;
        }
        _ => {}
    }

    if let Some(payload) = payload.as_object_mut() {
        payload.insert("headers".to_string(), headers_values.into());
    } else {
        return (StatusCode::BAD_REQUEST).into_response();
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs() as usize;

    let source_org = payload
        .get("organization")
        .and_then(|org| org.get("login"))
        .and_then(|value| value.as_str())
        .unwrap_or("no_org");
    let source_repo = payload
        .get("repository")
        .and_then(|org| org.get("name"))
        .and_then(|value| value.as_str())
        .unwrap_or("no_repo");
    let source_event = payload
        .get("headers")
        .and_then(|org| org.get("X-GitHub-Event"))
        .and_then(|value| value.as_str())
        .unwrap_or("no_event");
    let source_action = payload
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or("no_action");

    let event_metadata = hec_event::EventMetaData::new(
        now,
        "github".to_string(),
        "github_json".to_string(),
        format!(
            "{}:{}:{}:{}",
            source_org, source_repo, source_event, source_action
        ),
        config.hostname.to_string(),
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
        .unwrap_or("")
        .split('=')
        .next_back()
        .unwrap_or("")
        .as_bytes();

    let mut hash_bytes = vec![0; github_hash.len() / 2];

    hex_decode(github_hash, &mut hash_bytes)?;

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");

    mac.update(body);

    mac.verify_slice(&hash_bytes[..])?;

    Ok(())
}

struct AppSecrets {
    token: String,
    github_hmac_secret: String,
    github_app_id: String,
    github_app_secret: String,
}

async fn get_secrets() -> Result<AppSecrets, Box<dyn std::error::Error>> {
    info!("Getting Default Azure Credentials");
    let credential = Arc::new(DefaultAzureCredential::create(
        TokenCredentialOptions::default(),
    )?);

    info!("KeyVault Secret Client created");
    let keyvault_name = std::env::var("KEY_VAULT_NAME").expect("KEY_VAULT_NAME MUST be set");
    let keyvault_url = format!("https://{keyvault_name}.vault.azure.net");
    let client = KeyvaultClient::new(&keyvault_url, credential.clone())?.secret_client();

    info!("KeyVault: getting '{}'", &"SPLUNK-HEC-TOKEN");
    let token = client.get("SPLUNK-HEC-TOKEN").await?.value.to_string();

    info!("KeyVault: getting '{}'", &"GITHUB-HMAC-SECRET");
    let github_hmac_secret = client.get("GITHUB-HMAC-SECRET").await?.value.to_string();

    info!("KeyVault: getting '{}'", &"github-app-id");
    let github_app_id = client.get("github-app-id").await?.value.to_string();

    info!("KeyVault: getting '{}'", &"github-app-secret");
    let github_app_secret = client.get("github-app-secret").await?.value.to_string();

    Ok(AppSecrets {
        token,
        github_hmac_secret,
        github_app_id,
        github_app_secret,
    })
}

#[derive(Debug, Clone)]
enum ValidationError {
    MacError(hmac::digest::MacError),
    MissingHeader,
    #[allow(dead_code)]
    FasterHex(faster_hex::Error),
}

impl From<faster_hex::Error> for ValidationError {
    fn from(value: faster_hex::Error) -> Self {
        ValidationError::FasterHex(value)
    }
}

impl From<hmac::digest::MacError> for ValidationError {
    fn from(value: hmac::digest::MacError) -> Self {
        ValidationError::MacError(value)
    }
}
