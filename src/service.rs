use reqwest::Client;

#[derive(Debug, Clone)]
pub struct Service {
    pub(crate) url: String,
    pub(crate) token: String,
    pub(crate) client: Client,
}

impl Service {
    pub fn new(url: String, token: String) -> Service {
        let client = Client::builder().build().unwrap();
        Service { url, token, client }
    }

    // pub async fn send_events(&self, events: Vec<String>) {

    //     let token = format!("Splunk {} ", self.token.clone());
    //     let url = self.url.clone();

    //     for event in events {
    //         println!("Event : {}",event);

    //         let client = Client::builder().build().unwrap();

    //         let response = client
    //                 .post(&url)
    //                 .header("AUTHORIZATION", &token)
    //                 .header("CONTENT_TYPE", "application/json")
    //                 .body(event)
    //                 .send().await
    //                 .unwrap();

    //         println!("Response : {}, Text : {}", response.status(), response.text().await.unwrap())
    //     }
    // }

    pub async fn send_event(&self, event: String) {
        let token = format!("Splunk {} ", self.token.clone());
        let url = self.url.clone();

        //println!("Event : {}", event);

        //let client = Client::builder().build().unwrap();

        let response = self
            .client
            .post(&url)
            .header("AUTHORIZATION", &token)
            .header("CONTENT_TYPE", "application/json")
            .body(event)
            .send()
            .await
            .unwrap();

        println!(
            "Response : {}, Text : {}",
            response.status(),
            response.text().await.unwrap()
        )
    }
}
