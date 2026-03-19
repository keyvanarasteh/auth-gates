# Telemetry Server (`server.rs`)

The `server` feature spawns a lightweight `axum` instance capable of receiving instructions to trigger testing processes over REST, and broadcasting live output over an integrated WebSocket.

## Why use the Telemetry Server?
If you link `qicro-auth-gates` directly as a library, you only get CLI outputs `println!` and a returned `FinalReport` object.

With the server running (e.g., exposed on `0.0.0.0:3001` or another designated socket), developers can connect modern web dashboards (like Svelte or React apps) via WebSockets to see an analysis unfold in real-time.

## Architecture
- **Rest API (`/api/run`)**: Accepts HTTP `POST` requests structured exactly like a serialized `TargetConfig`. Invoking this API immediately spawns a background `tokio::spawn` task that begins the Fuzzer and stress analysis suite.
- **WebSocket Feed (`/ws`)**: A live `tokio-tungstenite` upgrade endpoint connecting directly to the `Analyzer`'s broadcast `Sender`. As the tool executes 5000 requests per second, telemetry intervals are sampled and pushed back across this WebSocket formatted as JSON `LiveUpdate` messages.

**Feature Activation**: Ensure `server` is added in `Cargo.toml`:
```toml
[dependencies]
qicro-auth-gates = { path = "features/auth-gates-core", features = ["server"] }
```
