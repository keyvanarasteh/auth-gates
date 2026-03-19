use crate::models::{color_status, color_time, print_headers_highlight, EngineMessage, FinalReport, LiveUpdate, Protocol, TargetConfig, AuthMethod};
use colored::*;
use futures_util::future::join_all;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use futures_util::SinkExt;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use url::Url;

pub struct ReqResult {
    pub id: u64,
    pub status: u16,
    pub elapsed_ms: f64,
    pub rl_headers: Vec<(String, String)>,
    pub all_headers: Vec<(String, String)>,
    pub body_preview: String,
    pub waf_detected: bool,
}

pub struct Analyzer {
    client: Client,
    log_tx: Option<tokio::sync::broadcast::Sender<EngineMessage>>,
}

impl Analyzer {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(15))
                .pool_max_idle_per_host(100)
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::default())
                .build()
                .unwrap(),
            log_tx: None,
        }
    }

    pub fn with_logging(mut self, tx: tokio::sync::broadcast::Sender<EngineMessage>) -> Self {
        self.log_tx = Some(tx);
        self
    }

    fn log_str(&self, msg: String, level: &str) {
        if let Some(tx) = &self.log_tx {
            let _ = tx.send(EngineMessage::Log { msg, level: level.to_string() });
        }
    }

    fn broadcast(&self, msg: EngineMessage) {
        if let Some(tx) = &self.log_tx {
            let _ = tx.send(msg);
        }
    }

    pub async fn fire_one(&self, id: u64, config: &TargetConfig) -> ReqResult {
        let t0 = Instant::now();
        let mut headers = reqwest::header::HeaderMap::new();
        
        headers.insert("User-Agent", "qicro-auth-gates/1.0".parse().unwrap());
        
        for (k, v) in &config.custom_headers {
            if let Ok(hk) = http::header::HeaderName::from_bytes(k.as_bytes()) {
                if let Ok(hv) = http::header::HeaderValue::from_str(v) {
                    headers.insert(hk, hv);
                }
            }
        }

        config.auth.apply(&mut headers);

        let mut req = self.client.request(config.method.clone(), &config.url)
            .headers(headers);

        if let Some(body) = &config.body {
            req = req.body(body.clone());
        }

        let resp = req.send().await;

        match resp {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
                let all_headers: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("?").to_string()))
                    .collect();

                let rl_headers: Vec<(String, String)> = all_headers
                    .iter()
                    .filter(|(k, _)| {
                        let kl = k.to_lowercase();
                        kl.contains("ratelimit") || kl.contains("retry-after")
                    })
                    .cloned()
                    .collect();

                let body = resp.text().await.unwrap_or_default();
                
                let mut title = String::new();
                if let Some(start) = body.find("<title>") {
                    if let Some(end) = body[start..].find("</title>") {
                        title = body[start + 7..start + end].trim().to_string();
                    }
                }

                let mut preview = body.chars().take(120).collect::<String>().replace('\n', " ");
                if !title.is_empty() {
                    preview = format!("[TITLE: {}] {}", title, preview);
                }

                let mut waf_detected = false;
                if status == 403 || status == 429 {
                    let body_lc = body.to_lowercase();
                    let headers_lc = format!("{:?}", all_headers).to_lowercase();
                    
                    if body_lc.contains("cloudflare") || body_lc.contains("ray id") || headers_lc.contains("cf-ray") {
                        waf_detected = true;
                    } else if body_lc.contains("awswaf") || headers_lc.contains("x-amzn-waf") {
                        waf_detected = true;
                    } else if body_lc.contains("akamai") || headers_lc.contains("ak-grn") {
                        waf_detected = true;
                    } else if body_lc.contains("sucuri") || headers_lc.contains("x-sucuri-id") {
                        waf_detected = true;
                    } else if body_lc.contains("imperva") || body_lc.contains("incapsula") || headers_lc.contains("x-iinfo") {
                        waf_detected = true;
                    } else if body_lc.contains("f5") || headers_lc.contains("x-csh-trace") {
                        waf_detected = true;
                    }
                }

                ReqResult { id, status, elapsed_ms: elapsed, rl_headers, all_headers, body_preview: preview, waf_detected }
            }
            Err(e) => {
                ReqResult {
                    id,
                    status: 0,
                    elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
                    rl_headers: vec![],
                    all_headers: vec![("error".into(), e.to_string())],
                    body_preview: e.to_string(),
                    waf_detected: false,
                }
            }
        }
    }

    pub async fn run_test(&self, config: TargetConfig) -> FinalReport {
        if config.protocol == Protocol::WebSocket {
            return WsAnalyzer::run_ws_test(config, self.log_tx.clone()).await;
        }

        let msg = format!("🚀 STARTING ANALYSIS: {} [{}]", config.name, config.url);
        println!("\n{}", msg.cyan().bold());
        self.log_str(msg, "warning");
        
        // --- EXTRACTION FROM STUDENT HOMEWORKS ---
        let mut api_endpoints = None;
        if config.run_api_fuzzer {
            let msg_fuzz = "Running API Endpoint Fuzzer...".to_string();
            println!("\n{}", msg_fuzz.cyan());
            self.log_str(msg_fuzz, "info");
            
            let default_words = vec![
                "api", "v1", "v2", "admin", "users", "auth", "login", "status", "health", "metrics"
            ];
            
            let words_strings = config.fuzzer_wordlist.clone().unwrap_or_else(|| {
                default_words.iter().map(|&s| s.to_string()).collect()
            });
            // convert to &str slices
            let word_slices: Vec<&str> = words_strings.iter().map(|s| s.as_str()).collect();
            
            let results = crate::fuzzer::discover_endpoints(&config.url, &word_slices, 10).await;
            for r in &results {
                let icon = match r.classification {
                    crate::fuzzer::EndpointClassification::Public => "🟢",
                    crate::fuzzer::EndpointClassification::Protected => "🟡",
                    crate::fuzzer::EndpointClassification::Forbidden => "🔴",
                    _ => "⚪",
                };
                let status_msg = format!("  {} {} [{:?}] -> {}", icon, r.url, r.classification, r.status);
                println!("{}", status_msg);
                self.log_str(status_msg, "info");
            }
            api_endpoints = Some(results);
        }

        let mut ws_endpoints = None;
        if config.run_ws_discovery {
            let msg_ws = "Running WebSocket Auto-Discovery...".to_string();
            println!("\n{}", msg_ws.cyan());
            self.log_str(msg_ws, "info");
            
            let results = crate::ws_discovery::discover_websockets(&config.url, 5).await;
            for r in &results {
                let icon = if r.is_open { "🟢" } else { "🔴" };
                let ws_msg = format!("  {} {} - {}", icon, r.url, r.message);
                println!("{}", ws_msg);
                self.log_str(ws_msg, if r.is_open { "success" } else { "error" } );
            }
            ws_endpoints = Some(results);
        }
        // ------------------------------------------
        
        let c_total = AtomicU64::new(0);
        let status_map = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let mut detected_limit = false;
        let mut latency_samples = Vec::new();
        let mut security_headers = Vec::new();
        let mut first_429: Option<u64> = None;

        let msg0 = "Phase 0: Single Probe".to_string();
        println!("{}", msg0.bold());
        self.log_str(msg0, "info");
        
        let probe = self.fire_one(0, &config).await;
        latency_samples.push(probe.elapsed_ms);
        
        for (k, v) in &probe.rl_headers {
            security_headers.push((k.clone(), v.clone()));
        }

        let msg_res = format!("  Status: {}  Time: {}", color_status(probe.status), color_time(probe.elapsed_ms));
        println!("{}", msg_res);
        self.log_str(msg_res, "info");
        
        self.broadcast(EngineMessage::Update(LiveUpdate {
            id: 0,
            status: probe.status,
            elapsed_ms: probe.elapsed_ms,
            waf_detected: probe.waf_detected,
        }));
        if !probe.all_headers.is_empty() {
             println!("  Headers:");
             print_headers_highlight(&probe.all_headers);
        }

        {
            let mut sm = status_map.lock().await;
            *sm.entry(probe.status).or_insert(0) += 1;
        }

        if probe.status == 429 {
            detected_limit = true;
            first_429 = Some(0);
        } else {
            let mut active_config = config.clone();
            if let Some(login_config) = config.pre_test_login {
                println!("\n{}", "🔑 Attempting Login-then-test...".yellow().bold());
                let login_res = self.fire_one(0, &login_config).await;
                println!("   Login Status: {}  Time: {}", color_status(login_res.status), color_time(login_res.elapsed_ms));
                
                if let Ok(json) = serde_json::from_str::<Value>(&login_res.body_preview) {
                    let token = json["token"].as_str()
                        .or(json["accessToken"].as_str())
                        .or(json["data"]["token"].as_str());
                    
                    if let Some(t) = token {
                        println!("   {} Found token, applying to analyzer.", "✅".green());
                        active_config.auth = AuthMethod::Bearer(t.to_string());
                    } else {
                        println!("   {} No token found in response, continuing with original auth.", "⚠️".yellow());
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;

            for phase in &config.phases {
                if detected_limit { break; }
                
                let msg_ph = format!("── Phase: {} ({} reqs, {} concurrency) ──", phase.label, phase.count, phase.concurrency);
                println!("\n{}", msg_ph.yellow());
                self.log_str(msg_ph, "warning");
                
                let sem = Arc::new(Semaphore::new(phase.concurrency));
                let mut handles = Vec::new();

                for i in 1..=phase.count {
                    let sem = sem.clone();
                    let config_clone = active_config.clone();
                    let client_clone = self.clone_self();

                    handles.push(tokio::spawn(async move {
                        let _permit = sem.acquire().await.unwrap();
                        client_clone.fire_one(i, &config_clone).await
                    }));
                }

                let results = join_all(handles).await;
                for res in results {
                    let r = res.expect("Task failed");
                    {
                        let mut sm = status_map.lock().await;
                        *sm.entry(r.status).or_insert(0) += 1;
                    }
                    c_total.fetch_add(1, Ordering::Relaxed);
                    
                    self.broadcast(EngineMessage::Update(LiveUpdate {
                        id: r.id,
                        status: r.status,
                        elapsed_ms: r.elapsed_ms,
                        waf_detected: r.waf_detected,
                    }));

                    if r.waf_detected {
                        println!("   {} {}", "🛡️ WAF/Cloudflare DETECTED!".bold().red(), "Challenge page or 403/429 block encountered.".red());
                    }

                    if r.status == 429 && !detected_limit {
                        detected_limit = true;
                        first_429 = Some(r.id);
                        let msg_rl = format!("🚨 RATE LIMITED at request #{}", r.id);
                        println!("\n  {}", msg_rl);
                        self.log_str(msg_rl, "error");
                        print_headers_highlight(&r.all_headers);
                        
                        for (k, v) in &r.rl_headers {
                            if !security_headers.iter().any(|(sk, _)| sk == k) {
                                security_headers.push((k.clone(), v.clone()));
                            }
                        }
                    }
                    
                    if latency_samples.len() < 100 {
                        latency_samples.push(r.elapsed_ms);
                    }
                }
                
                let msg_comp = format!("   Completed {} requests in this phase.", phase.count);
                println!("{}", msg_comp);
                self.log_str(msg_comp, "success");
            }
        }

        let final_status_map = status_map.lock().await.clone();
        let total = final_status_map.values().sum();

        let report = FinalReport {
            target_name: config.name.clone(),
            target_url: config.url.clone(),
            total_requests: total,
            status_breakdown: final_status_map,
            rate_limited: detected_limit,
            first_429_at: first_429,
            latency_samples,
            security_headers,
            api_endpoints,
            ws_endpoints,
        };

        if config.generate_html_report {
            let rpt_msg = format!("Generating Static HTML Dashboard for {}...", report.target_name);
            println!("\n{}", rpt_msg.cyan());
            self.log_str(rpt_msg, "info");
            
            std::fs::create_dir_all("reports").ok();
            let safe_name = report.target_name.replace(" ", "_").to_lowercase();
            let path = format!("reports/{}.html", safe_name);
            
            if let Err(e) = crate::html_report::generate_dashboard(&report, &path) {
                let err_msg = format!("Failed to generate HTML report: {}", e);
                println!("{}", err_msg.red());
                self.log_str(err_msg, "error");
            } else {
                let succ_msg = format!("✨ HTML Dashboard generated at {}", path);
                println!("{}", succ_msg.green().bold());
                self.log_str(succ_msg, "success");
            }
        }

        self.broadcast(EngineMessage::Final(report.clone()));
        report
    }

    fn clone_self(&self) -> Self {
        Self { 
            client: self.client.clone(),
            log_tx: self.log_tx.clone(),
        }
    }
}

pub struct WsAnalyzer;

impl WsAnalyzer {
    pub async fn test_connection(_id: u64, config: &TargetConfig) -> (u16, f64) {
        let t0 = Instant::now();
        let url_res = Url::parse(&config.url);
        
        if let Err(_) = url_res {
            return (0, t0.elapsed().as_secs_f64() * 1000.0);
        }
        let url = url_res.unwrap();

        let mut request = match url.into_client_request() {
            Ok(req) => req,
            Err(_) => return (0, t0.elapsed().as_secs_f64() * 1000.0),
        };

        request.headers_mut().insert("User-Agent", "Auth-Gates-Analyzer/1.0".parse().unwrap());

        for (k, v) in &config.custom_headers {
            if let Ok(hk) = http::header::HeaderName::from_bytes(k.as_bytes()) {
                if let Ok(hv) = http::header::HeaderValue::from_str(v) {
                    request.headers_mut().insert(hk, hv);
                }
            }
        }

        for (k, v) in config.auth.headers() {
            if let Ok(hk) = http::header::HeaderName::from_bytes(k.as_bytes()) {
                if let Ok(hv) = http::header::HeaderValue::from_str(&v) {
                    request.headers_mut().insert(hk, hv);
                }
            }
        }

        match connect_async(request).await {
            Ok((mut ws_stream, _)) => {
                let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
                let _ = ws_stream.close(None).await;
                (101, elapsed) 
            }
            Err(e) => {
                let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
                let status = match e {
                    tokio_tungstenite::tungstenite::Error::Http(resp) => resp.status().as_u16(),
                    tokio_tungstenite::tungstenite::Error::Io(_) => 503,
                    _ => 500,
                };
                (status, elapsed)
            }
        }
    }

    pub async fn test_message_rate_limit(config: &TargetConfig, count: u64) -> (u16, f64, u64) {
        let t0 = Instant::now();
        let url_res = Url::parse(&config.url);
        if let Err(_) = url_res { return (0, 0.0, 0); }
        let url = url_res.unwrap();

        let mut request = match url.into_client_request() {
            Ok(req) => req,
            Err(_) => return (0, 0.0, 0),
        };

        for (k, v) in config.auth.headers() {
            if let Ok(hk) = http::header::HeaderName::from_bytes(k.as_bytes()) {
                if let Ok(hv) = http::header::HeaderValue::from_str(&v) {
                    request.headers_mut().insert(hk, hv);
                }
            }
        }

        match connect_async(request).await {
            Ok((mut ws_stream, _)) => {
                let mut sent = 0;
                let mut last_status = 101;
                
                for _ in 0..count {
                    match ws_stream.send(Message::Text("ping".into())).await {
                        Ok(_) => sent += 1,
                        Err(_) => {
                            last_status = 403;
                            break;
                        }
                    }
                }
                let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
                let _ = ws_stream.close(None).await;
                (last_status, elapsed, sent)
            }
            Err(_) => (500, 0.0, 0),
        }
    }

    pub async fn run_ws_test(
        config: TargetConfig, 
        log_tx: Option<tokio::sync::broadcast::Sender<EngineMessage>>
    ) -> FinalReport {
        let broadcast = |msg: EngineMessage| {
            if let Some(tx) = &log_tx {
                let _ = tx.send(msg);
            }
        };

        let log_str = |msg: String, level: &str| {
            broadcast(EngineMessage::Log { msg, level: level.to_string() });
        };

        let msg = format!("🔌 STARTING WEBSOCKET ANALYSIS: {} [{}]", config.name, config.url);
        println!("\n{}", msg.magenta().bold());
        log_str(msg.clone(), "warning");
        
        let mut status_map = std::collections::HashMap::new();
        let mut detected_limit = false;
        let mut first_limit_at = None;
        let mut total_reqs = 0;
        let mut latency_samples = Vec::new();
        let security_headers = Vec::new(); 

        for phase in &config.phases {
            let is_msg_phase = phase.label.to_lowercase().contains("message") || phase.label.to_lowercase().contains("msg");
            
            if is_msg_phase {
                let msg_ph = format!("── WS Message Phase: {} ({} messages) ──", phase.label, phase.count);
                println!("\n{}", msg_ph.yellow());
                log_str(msg_ph, "info");
                
                let (status, elapsed, sent) = Self::test_message_rate_limit(&config, phase.count).await;
                *status_map.entry(status).or_insert(0) += 1;
                total_reqs += sent;
                
                let msg_res = format!("   Sent {} messages in {}ms. Status: {}", sent, color_time(elapsed), color_status(status));
                println!("{}", msg_res);
                log_str(msg_res, "info");

                broadcast(EngineMessage::Update(LiveUpdate {
                    id: total_reqs,
                    status,
                    elapsed_ms: elapsed,
                    waf_detected: false,
                }));
                
                if status != 101 && status != 0 {
                    detected_limit = true;
                    first_limit_at = Some(total_reqs);
                }
            } else {
                let msg_ph = format!("── WS Connection Phase: {} ({} conns, {} concurrency) ──", phase.label, phase.count, phase.concurrency);
                println!("\n{}", msg_ph.yellow());
                log_str(msg_ph, "info");
                
                let sem = Arc::new(tokio::sync::Semaphore::new(phase.concurrency));
                let mut handles = Vec::new();

                for i in 1..=phase.count {
                    let sem = sem.clone();
                    let config_clone = config.clone();
                    handles.push(tokio::spawn(async move {
                        let _permit = sem.acquire().await.unwrap();
                        Self::test_connection(i, &config_clone).await
                    }));
                }

                let results = futures_util::future::join_all(handles).await;
                for res in results {
                    let (status, elapsed) = res.expect("WS Task failed");
                    *status_map.entry(status).or_insert(0) += 1;
                    total_reqs += 1;
                    
                    if latency_samples.len() < 100 {
                        latency_samples.push(elapsed);
                    }

                    broadcast(EngineMessage::Update(LiveUpdate {
                        id: total_reqs,
                        status,
                        elapsed_ms: elapsed,
                        waf_detected: false,
                    }));

                    if status != 101 {
                        let msg_rl = format!("   🚨 Connection failed/limited at #{} (Status: {})", total_reqs, color_status(status));
                        println!("{}", msg_rl);
                        log_str(msg_rl, "error");
                    }
                }
                let msg_comp = format!("   Completed {} WS connections.", phase.count);
                println!("{}", msg_comp);
                log_str(msg_comp, "success");
            }
            if detected_limit { break; }
        }

        let report = FinalReport {
            target_name: config.name.clone(),
            target_url: config.url.clone(),
            total_requests: total_reqs,
            status_breakdown: status_map,
            rate_limited: detected_limit,
            first_429_at: first_limit_at,
            latency_samples,
            security_headers,
            api_endpoints: None,
            ws_endpoints: None,
        };

        if config.generate_html_report {
            let rpt_msg = format!("Generating Static HTML Dashboard for WS {}...", report.target_name);
            println!("\n{}", rpt_msg.cyan());
            log_str(rpt_msg, "info");
            
            std::fs::create_dir_all("reports").ok();
            let safe_name = report.target_name.replace(" ", "_").to_lowercase();
            let path = format!("reports/{}_ws.html", safe_name);
            
            if let Err(e) = crate::html_report::generate_dashboard(&report, &path) {
                let err_msg = format!("Failed to generate HTML report: {}", e);
                println!("{}", err_msg.red());
                log_str(err_msg, "error");
            } else {
                let succ_msg = format!("✨ HTML Dashboard generated at {}", path);
                println!("{}", succ_msg.green().bold());
                log_str(succ_msg, "success");
            }
        }

        broadcast(EngineMessage::Log { msg: format!("✅ WS Analysis Finished for {}", report.target_name), level: "success".to_string() });
        broadcast(EngineMessage::Final(report.clone()));
        report
    }
}
