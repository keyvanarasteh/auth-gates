use futures_util::StreamExt;
use reqwest::Url;
use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsDiscoveryResult {
    pub url: String,
    pub is_open: bool,
    pub message: String,
}

pub async fn discover_websockets(base_url: &str, concurrency: usize) -> Vec<WsDiscoveryResult> {
    let common_paths = vec![
        "/ws",
        "/socket.io",
        "/chat",
        "/messenger",
        "/stream",
        "/events",
        "/live",
        "/realtime",
        "/socket.io/?EIO=4&transport=websocket",
    ];

    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return vec![],
    };

    let stream = futures_util::stream::iter(common_paths.into_iter().map(|path| {
        let mut ws_url = base.clone();
        ws_url.set_path(path);
        
        let schema = match ws_url.scheme() {
            "http" => "ws",
            "https" => "wss",
            _ => "ws",
        };
        let _ = ws_url.set_scheme(schema);
        
        async move {
            let url_str = ws_url.to_string();
            
            let req = match url_str.clone().into_client_request() {
                Ok(r) => r,
                Err(e) => return WsDiscoveryResult {
                    url: url_str,
                    is_open: false,
                    message: format!("Invalid URL: {}", e),
                }
            };

            // Using select! with a timeout to avoid hanging connections
            let res = tokio::time::timeout(std::time::Duration::from_secs(3), connect_async(req)).await;

            match res {
                Ok(Ok((_, _))) => WsDiscoveryResult {
                    url: url_str,
                    is_open: true,
                    message: "Connection Successful (No initial auth required)".to_string(),
                },
                Ok(Err(e)) => {
                    let mut is_auth_error = false;
                    let err_msg = e.to_string();
                    if err_msg.contains("401") || err_msg.contains("403") {
                        is_auth_error = true;
                    }

                    WsDiscoveryResult {
                        url: url_str,
                        is_open: false,
                        message: if is_auth_error {
                            "Protected WebSocket (Requires Auth)".to_string()
                        } else {
                            format!("Failed to connect: {}", err_msg)
                        },
                    }
                },
                Err(_) => WsDiscoveryResult {
                    url: url_str,
                    is_open: false,
                    message: "Connection Timeout".to_string(),
                }
            }
        }
    }))
    .buffer_unordered(concurrency);

    let mut results = stream.collect::<Vec<_>>().await;
    
    // Sort results to bubble up successful connections first
    results.sort_by(|a, b| b.is_open.cmp(&a.is_open));
    
    results
}
