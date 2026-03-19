use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use crate::engine::Analyzer;
use crate::models::{TargetConfig, EngineMessage, FinalReport};
use futures_util::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct AppState {
    pub tx: broadcast::Sender<EngineMessage>,
}

#[derive(Deserialize)]
pub struct RunTargetRequest {
    pub config: TargetConfig,
}

#[derive(Serialize)]
pub struct RunTargetResponse {
    pub success: bool,
    pub report: Option<FinalReport>,
}

pub async fn start_server() -> anyhow::Result<()> {
    let (tx, _rx) = broadcast::channel(1000); // Larger buffer for live updates
    let state = AppState { tx };

    let app = Router::new()
        .route("/", get(root_info))
        .route("/health", get(health_check))
        .route("/api/health", get(health_check))
        .route("/api/v1/health", get(health_check))
        .route("/api/run", post(run_target))
        .route("/ws", get(ws_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 3001));
    println!("📡 Server listening on all interfaces: http://0.0.0.0:3001");
    println!("🔗 Local access: http://127.0.0.1:3001");
    
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn root_info() -> impl IntoResponse {
    Json(serde_json::json!({ 
        "engine": "qicro-auth-gates Telemetry Server",
        "status": "online",
        "api_v1": "/api/v1/health",
        "websocket": "/ws"
    }))
}

async fn health_check() -> impl IntoResponse {
    println!("🔍 Health check requested");
    Json(serde_json::json!({ 
        "status": "ok", 
        "version": "0.1.0-PRO",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn run_target(
    State(state): State<AppState>,
    Json(payload): Json<RunTargetRequest>,
) -> impl IntoResponse {
    let analyzer = Analyzer::new().with_logging(state.tx.clone());
    let config = payload.config;
    
    let report = analyzer.run_test(config).await;
    
    Json(RunTargetResponse {
        success: true,
        report: Some(report),
    })
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.tx.subscribe();

    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&msg) {
                if sender.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
        }
    });

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(text))) = receiver.next().await {
            println!("Received from WS: {}", text);
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };
}
