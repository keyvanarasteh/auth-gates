# Engine Module (`engine.rs`)

The `Analyzer` is the core of `qicro-auth-gates`. It processes a `TargetConfig` and executes a series of burst-request phases or probes based on the provided configuration.

## Key Features
- **High-Concurrency Execution**: Uses `tokio::sync::Semaphore` to dispatch concurrent HTTP/WebSocket requests effectively without overwhelming OS socket limits.
- **Latency Tracking**: Records individual request latency into `f64` samples, allowing metrics generation and average latency calculations in `html_report.rs`.
- **WAF Header Detection**: Parses server response headers (e.g., `Server`, `x-amz-cf-id`, `x-sucuri-id`, `CF-RAY`) to identify known Web Application Firewalls.
- **Stateful Authentication Lifecycle**: Can perform an initial "login" request as defined in `pre_test_login` and capture JSON paths out of the response (e.g. JWT tokens) to automatically inject into all subsequent test phases as Bearer tokens.

## Usage Matrix

If `config.protocol` is `Http`, the `Analyzer` will loop over `config.phases`. In each phase, an exact number of asynchronous web requests are executed using the provided method (GET, POST, HEAD, PUT) and payload.

If `config.protocol` is `WebSocket`, the `WsAnalyzer` extension boots up a `tokio-tungstenite` connector and attempts to hammer the socket endpoint with `Count` connections, measuring how many establish successfully versus connection resets or limit drops.

## Telemetry
Both HTTP and WS paths actively ping telemetry via `tokio::sync::broadcast` (`self.log_tx`). This powers the `server.rs` module, beaming live progress directly to attached browsers.
