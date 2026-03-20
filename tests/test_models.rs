use qicro_auth_gates::models::{AuthMethod, TargetConfig, Protocol, method_serde, color_status, color_time};
use reqwest::Method;
use std::collections::HashMap;

#[test]
fn test_auth_method_headers() {
    let mut map = http::HeaderMap::new();
    
    // Bearer
    let bearer = AuthMethod::Bearer("token123".to_string());
    bearer.apply(&mut map);
    assert_eq!(map.get("authorization").unwrap().to_str().unwrap(), "Bearer token123");
    
    // Cookie
    let cookie = AuthMethod::Cookie("session=xyz".to_string());
    cookie.apply(&mut map);
    assert_eq!(map.get("cookie").unwrap().to_str().unwrap(), "session=xyz");
    
    // Basic
    let basic = AuthMethod::Basic { user: "admin".to_string(), pass: "pass".to_string() };
    basic.apply(&mut map);
    assert!(map.get("authorization").unwrap().to_str().unwrap().starts_with("Basic "));
    
    // API Key
    let api_key = AuthMethod::ApiKey { key: "X-API-KEY".to_string(), value: "key123".to_string() };
    api_key.apply(&mut map);
    assert_eq!(map.get("x-api-key").unwrap().to_str().unwrap(), "key123");
}

#[test]
fn test_target_config_serialization() {
    let config = TargetConfig {
        name: "Test Target".to_string(),
        protocol: Protocol::Http,
        url: "http://example.com/api".to_string(),
        method: Method::POST,
        auth: AuthMethod::None,
        custom_headers: HashMap::new(),
        body: Some("{\"key\":\"value\"}".to_string()),
        phases: vec![],
        pre_test_login: None,
        run_api_fuzzer: false,
        run_ws_discovery: false,
        generate_html_report: true,
        fuzzer_wordlist: None,
    };
    
    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("POST"));
    assert!(json.contains("Test Target"));
    
    let deserialized: TargetConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.name, config.name);
    assert_eq!(deserialized.method, Method::POST);
}

#[test]
fn test_status_colorization() {
    let colored = color_status(200);
    let str_repr = format!("{:?}", colored);
    assert!(str_repr.contains("200"));
}

#[test]
fn test_time_colorization() {
    let fast = color_time(50.0);
    assert!(format!("{:?}", fast).contains("50"));
}
