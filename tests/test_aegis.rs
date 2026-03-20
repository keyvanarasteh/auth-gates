use qicro_auth_gates::aegis::fingerprint::DeviceFingerprint;
use qicro_auth_gates::aegis::geo_logic::is_impossible_travel;
use qicro_auth_gates::aegis::session_manager::{IdentityProfile, NetworkIntel, SessionStatus, UserSession};
use chrono::{Utc, TimeZone, Duration};

#[test]
fn test_device_fingerprint_similarity() {
    let fp1 = DeviceFingerprint {
        user_agent: "Mozilla".to_string(),
        platform: "Windows".to_string(),
        hardware_concurrency: 8,
        browser_engine: "V8".to_string(),
    };
    
    let fp2 = DeviceFingerprint {
        user_agent: "Mozilla".to_string(),
        platform: "Windows".to_string(),
        hardware_concurrency: 8,
        browser_engine: "V8".to_string(),
    };
    
    let score1 = fp1.calculate_similarity_score(&fp2);
    assert_eq!(score1, 100);
    
    let fp3 = DeviceFingerprint {
        user_agent: "Chrome".to_string(),
        platform: "Mac".to_string(),
        hardware_concurrency: 4,
        browser_engine: "WebKit".to_string(),
    };
    
    let score2 = fp1.calculate_similarity_score(&fp3);
    assert_eq!(score2, 0);
}

#[test]
fn test_geo_logic() {
    let time1 = Utc::now();
    let time2 = time1 + Duration::minutes(5); // 5 mins later
    
    // Impossible travel: NYC to London in 5 mins
    let is_impossible = is_impossible_travel(time1, time2, "NYC", "London");
    assert!(is_impossible);
    
    // Possible travel: same location
    let is_possible = is_impossible_travel(time1, time2, "NYC", "NYC");
    assert!(!is_possible);
    
    // Possible travel: 5 hours later
    let time3 = time1 + Duration::hours(5);
    let is_possible2 = is_impossible_travel(time1, time3, "NYC", "London");
    assert!(!is_possible2);
}

#[test]
fn test_user_session_audit() {
    let mut session = UserSession {
        session_id: "session123".to_string(),
        identity: IdentityProfile {
            email: "user@example.com".to_string(),
            linked_social: "@user".to_string(),
        },
        fingerprint: DeviceFingerprint {
            user_agent: "Agent".to_string(),
            platform: "OS".to_string(),
            hardware_concurrency: 4,
            browser_engine: "Engine".to_string(),
        },
        intel: NetworkIntel {
            ip_address: "1.1.1.1".to_string(),
            location: "Loc".to_string(),
            isp_org: "ISP".to_string(),
            is_vpn_proxy: false,
        },
        last_seen: Utc::now(),
        threat_score: 0,
        status: SessionStatus::Active,
    };
    
    let new_fp = DeviceFingerprint {
        user_agent: "Different".to_string(),
        platform: "Different".to_string(),
        hardware_concurrency: 2,
        browser_engine: "Different".to_string(),
    };
    
    let new_intel = NetworkIntel {
        ip_address: "2.2.2.2".to_string(),
        location: "Loc2".to_string(),
        isp_org: "VPNNNNN".to_string(),
        is_vpn_proxy: true,
    };
    
    session.deep_security_audit(new_fp, new_intel, true); // True for travel alert
    
    assert!(session.threat_score >= 120); // 100 diff fp + 70 travel + 50 vpn = 220
    assert_eq!(session.status, SessionStatus::Lockdown);
}
