# qicro-auth-gates

`qicro-auth-gates` is an advanced telemetry, rate limit analysis, and security testing crate designed natively for the Qicro environment. It provides burst request analysis, WAF detection, and active session monitoring via WebSockets.

## Capabilities
- 🚀 [**High-Concurrency Burst Testing**](docs/ENGINE.md): Uses `tokio::sync::Semaphore` to stress-test target endpoints with extreme throughput.
- 🛡️ [**WAF & Security Header Detection**](docs/ENGINE.md): Checks and parses server response headers for identifying barriers like Cloudflare, AWS WAF, Akamai, Sucuri, Imperva, and F5.
- 🔑 [**Multi-Auth Execution Configuration**](docs/MODELS.md): Testing setup using configurations like `Bearer`, `ApiKey`, `Basic`, and `Cookie` authentication, plus dynamic pre-test login injection.
- 🕵️ [**API Endpoint Fuzzer & HTML Reporting**](docs/FUZZER_AND_WS.md): Asynchronous wordlist iteration to uncover hidden endpoints, coupled with a beautiful static HTML dashboard generator.
- 🔌 [**Integrated WebSocket Discovery**](docs/FUZZER_AND_WS.md): Rapid `ws://` connection testing on potentially misconfigured WebSocket directories.
- 📡 [**Live Telemetry Server**](docs/SERVER.md): Spawns a lightweight Axum-based API and WS broadcast mechanism (via the `server` feature), tracking the testing suite's messages in real-time.
- 🛡️ [**Aegis Defensive Session Guard**](docs/AEGIS.md): Built-in backend identity guarding with Hardware Device Fingerprinting, Impossible geo-travel detection, and Session concurrency limits.

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
