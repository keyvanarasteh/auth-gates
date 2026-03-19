# Aegis Defensive Modules

The files strictly located under `src/aegis/*` comprise the "Blue Team" half of the `qicro-auth-gates` crate natively providing active application security inside Rust microservices.

## 1. Hardware Fingerprinting (`fingerprint.rs`)
Extracts, sanitizes, and deterministically hashes the incoming client connection into an immutable device token.
- Uses `Client IP`, `User-Agent`, `Accept-Language`, and specific `X-Forwarded-For` proxy headers.
- Outputs an MD5 or SHA256 deterministic token used as a secondary session lock. 
- Useful for stopping session hijacking. If the fingerprint randomly changes mid-session, Aegis automatically revokes the session.

## 2. Geo-Logic Routing (`geo_logic.rs`)
Integrates IP-to-Country blocking mechanisms native to Rust.
- Validates the derived IP against a static configuration (e.g., block requests originating from generic proxy VPS subnets).
- Enforces an `ALLOW_LIST` or `DENY_LIST` for strict origin verification.

## 3. Session Management (`session_manager.rs`)
Tracks the active concurrency and age of JSON Web Tokens (`Bearer`) and API keys across the application pool.
- Caps identical parallel sign-ins (e.g., restricts the same API token from executing requests simultaneously from 5 distinct IP addresses).
- Drops the least-recently configured session to enforce an `N-Max Active Devices` pattern.
