use chrono::{DateTime, Utc};

pub fn is_impossible_travel(
    last_time: DateTime<Utc>, 
    new_time: DateTime<Utc>, 
    last_loc: &str, 
    new_loc: &str
) -> bool {
    if last_loc != new_loc {
        let duration = new_time.signed_duration_since(last_time);
        
        if duration.num_minutes() < 10 {
            return true;
        }
    }
    false
}
