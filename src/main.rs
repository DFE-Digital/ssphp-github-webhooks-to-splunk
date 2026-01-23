use axum::{
    Router, extract::Json, http::{StatusCode, header::HeaderMap}, response::{IntoResponse, Response}, routing::post
};


#[tokio::main]
async fn main() {
    // build our application with a single route
    let app = Router::new()
                .route("/", post(root))
                .route("/foo",post(post_foo));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

}


async fn root(headers: HeaderMap, Json(mut payload): Json<serde_json::Value>) -> Response {
    let msg_headers = [
        "X-GitHub-Delivery",
        "X-Hub-Signature",
        "X-Hub-Signature-256",
        "X-GitHub-Event",
        "X-GitHub-Hook-ID",
        "X-GitHub-Hook-Installation-Target-ID",
        "X-GitHub-Hook-Installation-Target-Type"
    ];
    let mut headers_values = serde_json::Map::new();

    for msg_header in msg_headers{
        let Some(value) = headers.get(msg_header) else {continue;};
        let Ok(value) = value.to_str() else {continue;};
        headers_values.insert(msg_header.into(), value.to_string().into());
    }

    println!("header object : {:#?} ",headers_values);

    if let Some(payload) = payload.as_object_mut() {
        payload.insert("headers".to_string(), headers_values.into());
    }
    else {return (StatusCode::BAD_REQUEST).into_response();};

    println!("payload : {} ",payload);

    Json(payload).into_response()
}


async fn post_foo() {


}
