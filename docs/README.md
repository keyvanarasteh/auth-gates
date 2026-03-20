# 🛡️ Qicro Auth Gates Core

A powerful security analysis and gate-testing engine for the Qicro ecosystem.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Module Index](#module-index)
- [Quick Start](#quick-start)

## 🔍 Overview

`auth-gates-core` is a specialized tool designed to audit the security and resilience of REST and WebSocket endpoints. It combines a high-performance HTTP engine with discovery tools to identify rate-limiting thresholds, WAF presence, and undocumented routes.

## ✨ Features

-   **Stress Testing**: Multi-phase concurrency-controlled load testing.
-   **Automated Login**: Authenticates and captures tokens before running tests.
-   **WAF Identification**: Recognizes Cloudflare, AWS, Akamai, and other security layers.
-   **API Fuzzing**: Discovers common endpoints (v1, admin, health, etc.).
-   **WebSocket Discovery**: Probes for open WS hooks.
-   **HTML Reporting**: Generates interactive dashboards for analysis results.

## 📂 Module Index

-   [**Analyzer Engine**](analyzer.md): The core execution logic for HTTP and WebSocket tests.
-   [**Discovery Tools**](discovery.md): API fuzzing, WebSocket discovery, and reporting.
-   [**Models & Config**](models.md): Configuration schema and data structures.

## 🚀 Quick Start

```rust
use auth_gates_core::engine::Analyzer;
use auth_gates_core::models::{TargetConfig, Protocol};

#[tokio::main]
async fn main() {
    let analyzer = Analyzer::new();
    
    let config = TargetConfig {
        name: "Production API".to_string(),
        url: "https://api.example.com/v1/data".to_string(),
        protocol: Protocol::Http,
        // ... (other config)
        ..TargetConfig::default()
    };

    let report = analyzer.run_test(config).await;
    println!("Analysis complete. Total requests: {}", report.total_requests);
}
```
