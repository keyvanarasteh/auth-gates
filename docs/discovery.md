# 🔎 Discovery & Fuzzing Tools

The `auth-gates-core` includes automated discovery tools (in `fuzzer.rs` and `ws_discovery.rs`) to identify undocumented endpoints and potential security gaps.

## 📋 Table of Contents

- [API Endpoint Fuzzer](#api-endpoint-fuzzer)
- [WebSocket Discovery](#websocket-discovery)
- [Reporting](#reporting)

## 🛠️ API Endpoint Fuzzer

The `discover_endpoints` function scans a base URL for common API paths and classifies them based on their response.

### Classification
-   🟢 **Public**: Returns a success code (200-299) without authentication.
-   🟡 **Protected**: Returns 401 Unauthorized or 403 Forbidden with evidence of an auth requirement.
-   🔴 **Blocked/Forbidden**: Explicitly forbidden by the server or WAF.
-   ⚪ **Unknown**: Ambiguous response code.

### Usage
It uses a customizable wordlist (defaulting to common paths like `api`, `v1`, `admin`, `users`, etc.) and performs concurrent probing with a timeout.

## 🔌 WebSocket Discovery

The `discover_websockets` tool checks for the existence and state of WebSocket endpoints at a given base URL.

-   **Verification**: Attempts a handshake on potential WS paths.
-   **Status Reporting**: Identifies if the endpoint is open, requires specific subprotocols, or is blocked by the server.

## 📊 Reporting (`html_report.rs`)

The analyzer can generate a comprehensive, self-contained HTML dashboard of the findings.

-   **Visualizations**: Charts for latency distribution and status code breakdowns.
-   **Audit Trails**: Lists all security headers found and endpoint discovery results.
-   **WAF Evidence**: Documents any signatures that triggered WAF detection.
