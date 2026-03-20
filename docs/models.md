# 📦 Models & Configuration

The `models.rs` module defines the shared data structures for configuring security tests and interpreting results.

## 📋 Table of Contents

- [Target Configuration](#target-configuration)
- [Authentication Models](#authentication-models)
- [Reporting Structures](#reporting-structures)
- [Message Types](#message-types)

## ⚙️ Target Configuration (`TargetConfig`)

This is the primary input for the analyzer, usually serialized from JSON.

-   `name`: Label for the test target.
-   `url`: The base URL (HTTP/HTTPS/WS).
-   `protocol`: `Http` or `WebSocket`.
-   `method`: HTTP verb (GET, POST, etc.).
-   `auth`: The `AuthMethod` to use.
-   `custom_headers`: A map of additional headers to inject.
-   `phases`: A list of `PhaseConfig` defining the load profile.
-   `pre_test_login`: An optional nested `TargetConfig` for obtaining tokens.
-   `run_api_fuzzer`: Boolean flag to enable endpoint scanning.
-   `run_ws_discovery`: Boolean flag to enable WebSocket scanning.
-   `generate_html_report`: Boolean flag to trigger report generation.

## 🛡️ Authentication Models (`AuthMethod`)

An enum supporting various authentication schemes:
-   `None`
-   `Bearer(String)`: JWT token.
-   `ApiKey { key: String, value: String }`: e.g., `X-API-Key`.
-   `Basic { user, pass }`: Automatic Base64 encoding.
-   `Cookie(String)`: Raw cookie string.

## 📊 Reporting Structures

### `FinalReport`
The complete state of a finished analysis.
-   `status_breakdown`: A map of HTTP status codes to hit counts.
-   `rate_limited`: Whether a 429 was encountered.
-   `latency_samples`: Data for performance charts.
-   `security_headers`: Unique security/rate-limit headers captured.
-   `api_endpoints`: Results from the fuzzer.

### `LiveUpdate`
Incremental data sent during a test (Request ID, status, latency).

## ✉️ Message Types (`EngineMessage`)

A tagged enum for broadcasting engine state:
-   `Log`: Textual log message with a level (info, success, warning, error).
-   `Update`: A single `LiveUpdate`.
-   `Final`: The complete `FinalReport`.
