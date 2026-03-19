use crate::aegis::fingerprint::DeviceFingerprint;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum SessionStatus { Active, Compromised, Lockdown }

#[derive(Serialize, Deserialize, Debug)]
pub struct IdentityProfile {
    pub email: String,
    pub linked_social: String, 
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkIntel {
    pub ip_address: String,
    pub location: String,
    pub isp_org: String,
    pub is_vpn_proxy: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserSession {
    pub session_id: String,
    pub identity: IdentityProfile, 
    pub fingerprint: DeviceFingerprint,
    pub intel: NetworkIntel,
    pub last_seen: DateTime<Utc>,
    pub threat_score: u32,
    pub status: SessionStatus,
}

impl UserSession {
    pub fn deep_security_audit(&mut self, new_fp: DeviceFingerprint, new_intel: NetworkIntel, travel_alert: bool) {
        
        let similarity = self.fingerprint.calculate_similarity_score(&new_fp);
        if similarity < 100 { 
            self.threat_score += 100 - similarity; 
        }

        if travel_alert { 
            self.threat_score += 70; 
        }

        if new_intel.is_vpn_proxy {
            println!("🚨 THREAT: Suspicious connection detected from {}!", new_intel.isp_org);
            self.threat_score += 50;
        }

        if self.threat_score >= 50 {
            self.status = if self.threat_score >= 120 { SessionStatus::Lockdown } else { SessionStatus::Compromised };
            
            println!("\n📧 [INCIDENT RESPONSE] -> Security breach email dispatched to {}!", self.identity.email);
            println!("📲 [SOCIAL MEDIA] -> Incident notification sent to user via {}!", self.identity.linked_social);
            
            if self.status == SessionStatus::Lockdown {
                println!("🔒 [CRITICAL] Device and IP configuration blacklisted.");
            }
        }
    }
}
