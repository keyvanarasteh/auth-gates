use reqwest::{Client, Method};
use std::time::Duration;
use futures_util::StreamExt;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResult {
    pub url: String,
    pub status: u16,
    pub classification: EndpointClassification,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EndpointClassification {
    Public,
    Protected,
    Forbidden,
    NotFound,
    Other,
}

impl EndpointClassification {
    fn from_status(status: u16) -> Self {
        match status {
            200..=299 => EndpointClassification::Public,
            401 => EndpointClassification::Protected,
            403 => EndpointClassification::Forbidden,
            404 => EndpointClassification::NotFound,
            _ => EndpointClassification::Other,
        }
    }
}

pub async fn discover_endpoints(base_url: &str, wordlist: &[&str], concurrency: usize) -> Vec<DiscoveryResult> {
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| Client::new());

    let base = base_url.trim_end_matches('/');

    let stream = futures_util::stream::iter(wordlist.iter().map(|&path| {
        let url = format!("{}/{}", base, path.trim_start_matches('/'));
        let cli = client.clone();
        async move {
            let status = match cli.request(Method::HEAD, &url).send().await {
                Ok(resp) => resp.status().as_u16(),
                Err(_) => 0,
            };
            
            DiscoveryResult {
                url,
                status,
                classification: EndpointClassification::from_status(status),
            }
        }
    }))
    .buffer_unordered(concurrency);

    let mut results = stream.collect::<Vec<_>>().await;
    
    // Filter out 404s and 0s (errors)
    results.retain(|r| r.status != 404 && r.status != 0);
    
    // Sort by status code
    results.sort_by_key(|r| r.status);
    
    results
}
