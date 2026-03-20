use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};
use qicro_auth_gates::fuzzer::discover_endpoints;

#[tokio::test]
async fn test_discover_endpoints_basic() {
    let mock_server = MockServer::start().await;

    // Set up a mock for /api that returns 200
    Mock::given(method("HEAD"))
        .and(path("/api"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    // Set up a mock for /admin that returns 403
    Mock::given(method("HEAD"))
        .and(path("/admin"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&mock_server)
        .await;

    // Set up a mock for /missing that returns 404
    Mock::given(method("HEAD"))
        .and(path("/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let wordlist = vec!["api", "admin", "missing"];
    let mut results = discover_endpoints(&mock_server.uri(), &wordlist, 2).await;
    
    // 404s get filtered out, so we should only have 2 results (api and admin)
    assert_eq!(results.len(), 2);
    
    // Sort logic in fuzzer sorts by status code
    assert_eq!(results[0].url.ends_with("/api"), true);
    assert_eq!(results[0].status, 200);
    assert_eq!(format!("{:?}", results[0].classification), "Public");
    
    assert_eq!(results[1].url.ends_with("/admin"), true);
    assert_eq!(results[1].status, 403);
    assert_eq!(format!("{:?}", results[1].classification), "Forbidden");
}
