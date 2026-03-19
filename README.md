# qicro-auth-gates

`qicro-auth-gates` is an advanced telemetry, rate limit analysis, and security testing crate designed natively for the Qicro environment. It provides burst request analysis, WAF detection, and active session monitoring via WebSockets.

## Capabilities
- 🚀 **High-Concurrency Burst Testing**: Uses `tokio::sync::Semaphore` to stress-test target endpoints with extreme throughput.
- 🛡️ **WAF & Security Header Detection**: Advanced signature checks for identifying barriers like Cloudflare, AWS WAF, Akamai, Sucuri, Imperva, and F5.
- 🔑 **Multi-Auth Execution**: Effortless testing using `Bearer`, `ApiKey`, `Basic`, and `Cookie` authentication, plus the revolutionary **Stateful Login-Then-Test** workflow which grabs live JSON tokens mid-analysis.
- 🔌 **Integrated WebSocket Analysis**: Supports both raw `ping` frame messaging limits and burst connection load limits.
- 📡 **Live Telemetry Server**: Can spawn a lightweight Axum-based broadcast mechanism on `0.0.0.0:3001` (via the `server` feature), tracking the testing suite's `LiveUpdate` messages in real-time.
- 🛡️ **Aegis Defensive Session Guard**: Built-in backend identity guarding with Hardware Device Fingerprinting, Impossible geo-travel detection (Geo-velocity), ISP Reputation Intelligence, and Automated Incident Response (Lockdown).

## Features Let
* `default` - No default features to keep the minimal core library dependencies light.
* `server` - Activates the built-in Axum REST & WebSocket telemetry Server mapping (`/api/run` and `/ws`).

## Sample Usage

```rust
use qicro_auth_gates::models::{TargetConfig, PhaseConfig, AuthMethod, Protocol};
use qicro_auth_gates::engine::Analyzer;
use reqwest::Method;
use std::collections::HashMap;

#[tokio::main]
async fn main() {
    let analyzer = Analyzer::new();

    let config = TargetConfig {
        name: "Testing Qline Endpoint".to_string(),
        protocol: Protocol::Http,
        url: "https://app.qline.tech/api/v1/auth/login".to_string(),
        method: Method::POST,
        auth: AuthMethod::None,
        custom_headers: HashMap::new(),
        body: Some(r#"{"email":"hello@124.com","password":"123"}"#.to_string()),
        phases: vec![
            PhaseConfig { label: "Warmup".into(), count: 50, concurrency: 10 },
            PhaseConfig { label: "Nuke".into(), count: 1000, concurrency: 50 },
        ],
        pre_test_login: None,
    };

    let report = analyzer.run_test(config).await;
    println!("Total Requests Checked: {}", report.total_requests);
    println!("Rate Limited Blocked?: {}", report.rate_limited);
}
```

## Thanks

A huge thank you to the following contributors who helped us build features for this crate:
- [@azzizefe](https://github.com/azzizefe) (ID: 140910406)
- [@byznrckcc](https://github.com/byznrckcc) (ID: 184291089)
- [@melisakaradagg](https://github.com/melisakaradagg) (ID: 196482789)
- [@gizemkizilay](https://github.com/gizemkizilay) (ID: 202020053)
