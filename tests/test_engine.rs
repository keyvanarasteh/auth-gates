use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path, header_exists};
use qicro_auth_gates::engine::{Analyzer, ReqResult};
use qicro_auth_gates::models::{AuthMethod, TargetConfig, Protocol};
use reqwest::Method;
use std::collections::HashMap;

#[tokio::test]
async fn test_analyzer_fire_one_basic() {
    let mock_server = MockServer::start().await;
    
    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<title>It Works!</title> Welcome"))
        .mount(&mock_server)
        .await;

    let config = TargetConfig {
        name: "Test Target".to_string(),
        protocol: Protocol::Http,
        url: format!("{}/test", mock_server.uri()),
        method: Method::GET,
        auth: AuthMethod::None,
        custom_headers: HashMap::new(),
        body: None,
        phases: vec![],
        pre_test_login: None,
        run_api_fuzzer: false,
        run_ws_discovery: false,
        generate_html_report: false,
        fuzzer_wordlist: None,
    };

    let analyzer = Analyzer::new();
    let result: ReqResult = analyzer.fire_one(1, &config).await;

    assert_eq!(result.id, 1);
    assert_eq!(result.status, 200);
    assert_eq!(result.waf_detected, false);
    assert!(result.body_preview.contains("[TITLE: It Works!]"));
}

#[tokio::test]
async fn test_analyzer_waf_detection() {
    let mock_server = MockServer::start().await;
    
    // WAF is checked on 403 or 429
    Mock::given(method("GET"))
        .and(path("/waf"))
        .respond_with(ResponseTemplate::new(403).set_body_string("error ray id cloudflare block"))
        .mount(&mock_server)
        .await;

    let config = TargetConfig {
        name: "WAF Target".to_string(),
        protocol: Protocol::Http,
        url: format!("{}/waf", mock_server.uri()),
        method: Method::GET,
        auth: AuthMethod::None,
        custom_headers: HashMap::new(),
        body: None,
        phases: vec![],
        pre_test_login: None,
        run_api_fuzzer: false,
        run_ws_discovery: false,
        generate_html_report: false,
        fuzzer_wordlist: None,
    };

    let analyzer = Analyzer::new();
    let result = analyzer.fire_one(2, &config).await;

    assert_eq!(result.status, 403);
    assert_eq!(result.waf_detected, true);
}
