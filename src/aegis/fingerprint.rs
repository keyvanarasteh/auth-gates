use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceFingerprint {
    pub user_agent: String,
    pub platform: String,          
    pub hardware_concurrency: u32, 
    pub browser_engine: String,    
}

impl DeviceFingerprint {
    pub fn calculate_similarity_score(&self, other: &DeviceFingerprint) -> u32 {
        let mut score = 0;
        if self.user_agent == other.user_agent { score += 30; }
        if self.platform == other.platform { score += 30; }
        if self.hardware_concurrency == other.hardware_concurrency { score += 20; }
        if self.browser_engine == other.browser_engine { score += 20; }
        score
    }
}
