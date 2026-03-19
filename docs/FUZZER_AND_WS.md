# Fuzzer & WebSocket Auto-Discovery

This documentation covers the tooling provided by `fuzzer.rs`, `ws_discovery.rs`, and the reporting dashboard `html_report.rs`. These modules were extracted from high-quality student contributions to expand the offensive capabilities of `qicro-auth-gates`.

## 1. API Endpoint Fuzzer (`fuzzer.rs`)
The API Fuzzer asynchronously iterates through a provided wordlist against a target URL to uncover hidden or unlinked endpoints. 

- **Wordlist Support**: You can provide custom lists (e.g. `["admin", "v2/users", "staging"]`), or the fuzzer defaults to a standard Top 10 list if none is provided.
- **`HEAD` Method Scanning**: Uses HTTP `HEAD` to minimize bandwidth while querying endpoint presence.
- **Status Classification**:
  - `Public` (200-299)
  - `Protected` (401)
  - `Forbidden` (403)
  - `NotFound` (404) -- Silently filtered out to reduce noise.
  
To invoke this, flip `run_api_fuzzer: true` in your `TargetConfig`.

## 2. WebSocket Discovery (`ws_discovery.rs`)
The WS Discovery module performs rapid connection testing on potentially misconfigured WebSocket directories.

- Tries `ws://` schemes against the exact URL provided by standardizing upgrades natively across `tungstenite`.
- Returns an open/closed (true/false) metric for each endpoint based on whether the `101 Switching Protocols` handshake successfully authenticated.
- Used defensively to ensure unauthenticated WebSocket endpoints aren't inadvertently left fully accessible.

## 3. Static HTML Generator (`html_report.rs`)
After an analysis run, if `generate_html_report: true` is configured, a full-page formatted `reports/{target}.html` dashboard will be emitted.

- Aggregates WAF flags into a clean error-table.
- Compiles the Rate Limiting thresholds.
- Combines the raw Fuzzer and WS output into a polished badge-identified layout natively written with zero CSS dependencies.
