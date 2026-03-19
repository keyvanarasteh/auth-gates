use colored::*;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use http::header::{HeaderMap, HeaderName, HeaderValue};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Protocol {
    Http,
    WebSocket,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetConfig {
    pub name: String,
    pub protocol: Protocol,
    pub url: String,
    #[serde(with = "method_serde")]
    pub method: Method,
    pub auth: AuthMethod,
    pub custom_headers: HashMap<String, String>,
    pub body: Option<String>,
    pub phases: Vec<PhaseConfig>,
    pub pre_test_login: Option<Box<TargetConfig>>,
    #[serde(default)]
    pub run_api_fuzzer: bool,
    #[serde(default)]
    pub run_ws_discovery: bool,
    #[serde(default)]
    pub generate_html_report: bool,
    #[serde(default)]
    pub fuzzer_wordlist: Option<Vec<String>>,
}

pub mod method_serde {
    use reqwest::Method;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(method: &Method, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(method.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Method, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        Method::from_bytes(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhaseConfig {
    pub label: String,
    pub count: u64,
    pub concurrency: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum AuthMethod {
    None,
    Bearer(String),
    ApiKey { key: String, value: String },
    Basic { user: String, pass: String },
    Cookie(String),
}

impl AuthMethod {
    pub fn apply(&self, headers: &mut HeaderMap) {
        for (k, v) in self.headers() {
            if let Ok(hk) = HeaderName::from_bytes(k.as_bytes()) {
                if let Ok(hv) = HeaderValue::from_str(&v) {
                    headers.insert(hk, hv);
                }
            }
        }
    }

    pub fn headers(&self) -> Vec<(String, String)> {
        let mut res = Vec::new();
        match self {
            AuthMethod::None => {}
            AuthMethod::Bearer(token) => {
                let val = if token.starts_with("Bearer ") {
                    token.clone()
                } else {
                    format!("Bearer {}", token)
                };
                res.push(("Authorization".into(), val));
            }
            AuthMethod::ApiKey { key, value } => {
                res.push((key.clone(), value.clone()));
            }
            AuthMethod::Basic { user, pass } => {
                let auth = format!("{}:{}", user, pass);
                let encoded = b64_encode(&auth);
                res.push(("Authorization".into(), format!("Basic {}", encoded)));
            }
            AuthMethod::Cookie(cookie) => {
                res.push(("Cookie".into(), cookie.clone()));
            }
        }
        res
    }
}

fn b64_encode(input: &str) -> String {
    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD.encode(input)
}

pub fn color_status(code: u16) -> ColoredString {
    match code {
        0 => "ERR".red().bold(),
        200..=299 => format!("{}", code).green().normal(),
        300..=399 => format!("{}", code).blue().normal(),
        401 => "401 UNAUTH".yellow().normal(),
        429 => "429 RATE LIMITED".red().bold(),
        400..=499 => format!("{}", code).red().normal(),
        500..=599 => format!("{}", code).red().bold(),
        _ => format!("{}", code).yellow().normal(),
    }
}

pub fn color_time(ms: f64) -> ColoredString {
    if ms < 100.0 {
        format!("{:>6.0}ms", ms).green().normal()
    } else if ms < 300.0 {
        format!("{:>6.0}ms", ms).yellow().normal()
    } else {
        format!("{:>6.0}ms", ms).red().normal()
    }
}

pub fn print_headers_highlight(headers: &[(String, String)]) {
    for (k, v) in headers {
        let k_lower = k.to_lowercase();
        let is_rl = k_lower.contains("rate") || k_lower.contains("limit") || k_lower.contains("retry") || k_lower.contains("throttl");
        if is_rl {
            println!("    {}: {}", k.cyan().bold(), v.yellow().bold());
        } else {
            println!("    {}: {}", k.dimmed(), v);
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FinalReport {
    pub target_name: String,
    pub target_url: String,
    pub total_requests: u64,
    pub status_breakdown: std::collections::HashMap<u16, u64>,
    pub rate_limited: bool,
    pub first_429_at: Option<u64>,
    pub latency_samples: Vec<f64>,
    pub security_headers: Vec<(String, String)>,
    pub api_endpoints: Option<Vec<crate::fuzzer::DiscoveryResult>>,
    pub ws_endpoints: Option<Vec<crate::ws_discovery::WsDiscoveryResult>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LiveUpdate {
    pub id: u64,
    pub status: u16,
    pub elapsed_ms: f64,
    pub waf_detected: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "data")]
pub enum EngineMessage {
    Log { msg: String, level: String },
    Update(LiveUpdate),
    Final(FinalReport),
}

pub fn print_final_summary(report: &FinalReport) {
    println!(
        "\n{}\n{}\n{}\n",
        "╔══════════════════════════════════════════════════════╗"
            .cyan().bold(),
        "║                   📊 FINAL REPORT                    ║"
            .cyan().bold(),
        "╚══════════════════════════════════════════════════════╝"
            .cyan().bold(),
    );
    println!("  {}: {}", "Target".bold(), report.target_name);
    println!("  {}: {}", "URL".bold(), report.target_url);
    println!("  {}: {}", "Total Requests".bold(), report.total_requests);
    println!("  {}:", "Status Breakdown".bold());
    
    let mut codes: Vec<_> = report.status_breakdown.keys().collect();
    codes.sort();
    for code in codes {
        let count = report.status_breakdown.get(code).unwrap();
        println!("    {}: {}", color_status(*code), count);
    }

    println!();
    if report.rate_limited {
        println!("  {}", "🚨 RATE LIMITING DETECTED!".red().bold());
        if let Some(at) = report.first_429_at {
            println!("  {} First 429 triggered at request #{}", "⚡".yellow(), at);
        }
    } else {
        println!("  {}", "✅ NO RATE LIMITING DETECTED".green().bold());
    }
    println!();
}
