# 🚀 Auth Gate Analyzer Engine

The `Analyzer` (in `engine.rs`) is the core execution engine for security analysis, rate-limit testing, and WAF detection.

## 📋 Table of Contents

- [Overview](#overview)
- [Request Execution](#request-execution)
- [Analysis Phases](#analysis-phases)
- [WAF Detection](#waf-detection)
- [WebSocket Analysis](#websocket-analysis)

## 🔍 Overview

The engine uses `reqwest` for high-performance HTTP(S) requests and `tokio-tungstenite` for WebSocket interactions. it is designed for asynchronous, concurrent execution with built-in logging and live update broadcasting.

## 🛠️ Request Execution

### `fire_one`
Executes a single, isolated request to the target.
-   Applies custom headers and authentication (Bearer, API Key, Basic, Cookie).
-   Captures precise timing (ms).
-   Extracts Rate-Limit headers (`X-RateLimit-*`, `Retry-After`).
-   Identifies WAF signatures in headers and body.

### Authentication Methods
-   **None**: Public access.
-   **Bearer**: JWT-based auth.
-   **ApiKey**: Custom header key/value pair.
-   **Basic**: Standard Base64 encoded credentials.
-   **Cookie**: Sessions persisted via cookies.

## 📊 Analysis Phases

The analyzer supports multi-phase stress testing to identify rate-limiting thresholds:
1.  **Phase 0: Single Probe**: Establishes a baseline for latency and server signatures.
2.  **Pre-Test Login**: If configured, the analyzer performs a login request, extracts a token automatically, and applies it to the subsequent test phases.
3.  **Configurable Phases**: Runs a specified number of requests with a controlled concurrency level (multi-threading via `tokio::sync::Semaphore`).

## 🛡️ WAF Detection

The engine can automatically identify various Web Application Firewalls and CDNs based on response behavior (403/429 status) and signature keywords:
-   **Cloudflare**: Ray IDs, `cf-ray` headers.
-   **AWS WAF**: `x-amzn-waf` headers.
-   **Akamai**: `ak-grn` headers.
-   **Imperva/Incapsula**: `x-iinfo` headers.
-   **F5**, **Sucuri**, and more.

## 🔌 WebSocket Analysis (`WsAnalyzer`)

Specialized logic for testing WebSocket connectivity and message-level rate limits:
-   **Connection Testing**: Measures latency of the initial handshake.
-   **Message Fuzzing**: Sends a burst of messages over a single connection to test message-level throttling.
